#!/usr/bin/env python3
"""disk_stream_scanner.py — private, heuristic static-triage scanner.

Offline / privacy policy
------------------------
* No AI APIs, cloud scanners, telemetry, uploads, or model downloads.
* The optional ``--s3-bucket/--s3-key`` mode opens one read-only HTTPS stream to an
  AWS S3 endpoint selected by ``AWS_ENDPOINT_URL_S3`` (default local-style
  ``http://127.0.0.1:4566``, matching LocalStack). AWS receives those request
  metadata and any configured signing credentials if they are present. Results,
  taint paths, and file content are never transmitted to an AI service.
* The "AI Confidence Score" is a deterministic embedded TF-IDF/logistic scoring
  layer implemented with the Python standard library only. It is not a neural
  network runtime, not a downloaded model, and not a guarantee that a finding is
  real or exploitable.

Scope and safety limits
-----------------------
Static analysis cannot prove safety and cannot guarantee zero-day discovery.
Use this as a pre-review filter and validate findings in authorized testing.

Memory model
------------
ZIP/TAR/TAR.GZ leaf members are opened as binary streams and consumed in
bounded read blocks; they are not written to disk and are not retained as
whole-member byte strings before scanning. S3 objects and nested archives keep
their already supplied parent archive bytes in memory, best-effort capped by
``--max-member-bytes`` (default 128 MiB), while Python AST analysis additionally
retains only up to 2 MiB of a Python source. Chunk reads still request at most
``104,857,600`` bytes per cycle; that does **not** hard-cap process RSS.
"""

from __future__ import annotations

import argparse
import ast
import concurrent.futures
import gc
import hashlib
import hmac
import io
import os
import re
import stat
import sys
import tarfile
import threading
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import BinaryIO, Callable, Deque, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    tomllib = None  # type: ignore[assignment]

VERSION = "2.2.0"
DEFAULT_READ_CHUNK_SIZE = 104_857_600
MAX_PHYSICAL_LINE_BYTES = 2_097_152
MAX_PENDING_LINE_BYTES = 8_388_608
MAX_AST_SOURCE_BYTES = 2_097_152
MAX_SANITIZER_SPAN = 40_960
DEFAULT_MAX_MEMBER_BYTES = 134_217_728
DEFAULT_MAX_CONCURRENT_FILES = 4
DEFAULT_MIN_AI_CONFIDENCE = 0.55
GUI_MOUSE_THRESHOLD = 0.72

CODE_EXTENSIONS = {
    ".c", ".cc", ".cfg", ".conf", ".cpp", ".cs", ".css", ".go", ".h", ".hh",
    ".hpp", ".htm", ".html", ".ini", ".java", ".js", ".json", ".jsx", ".kt",
    ".kts", ".lua", ".m", ".md", ".mm", ".php", ".pl", ".pm", ".ps1", ".py",
    ".rb", ".rs", ".sh", ".sql", ".swift", ".toml", ".ts", ".tsx", ".txt",
    ".xml", ".yaml", ".yml",
}
LOG_EXTENSIONS = {".log"}
ARCHIVE_EXTENSIONS = {".zip", ".tgz"}
DEFAULT_SOURCE_EXTENSIONS = CODE_EXTENSIONS | LOG_EXTENSIONS | {".tar", ".tar.gz", ".tgz", ".zip"}

PYTHON_INPUT_NAMES = {
    "input", "raw_input", "sys.argv", "request", "requests", "environ", "wsgi.input",
    "query", "params", "args", "form", "values", "data", "json", "files", "cookies",
    "headers", "body", "payload", "stdin", "socket", "recv", "recvfrom", "readline",
    "read", "getenv", "os.getenv", "os.environ", "flask.request", "django.http.HttpRequest",
}
GENERIC_SYMBOL_INPUT_WORDS = {
    "getenv", "stdin", "argv", "argc", "param", "params", "query", "request", "requests",
    "req", "res", "body", "form", "cookie", "cookies", "header", "headers", "arg", "args",
    "input", "payload", "uri", "url", "filename", "filepath", "path", "file", "upload",
    "post", "get", "put", "env", "origin", "session", "socket", "stdin",
}

NEGATIVE_SANITIZER_WEIGHT = -2.35
NEUTRAL_CONTEXT_WEIGHT = 0.25

# Embedded, hand-written TF-IDF vocabulary. This is deterministic standard-library
# data; no model is downloaded, loaded, or invoked over the network.
TF_IDF_VOCABULARY: Dict[str, Tuple[float, float]] = {
    "__bias__": (0.0, -0.55),
    "absint": (1.00, 0.22), "addslashes": (0.72, -1.85), "allowlist": (1.05, -1.80),
    "argv": (0.85, 0.45), "assert": (0.60, 0.20), "basename": (1.05, -1.45),
    "cbc": (0.85, 0.35), "cert": (0.75, -0.90), "cgi": (0.90, 0.35),
    "check": (0.70, -0.75), "cmd": (0.90, 0.55), "command": (0.90, 0.55),
    "concat": (0.65, 0.35), "cookie": (0.90, 0.45), "create": (0.35, 0.05),
    "database": (0.75, 0.30), "decode": (0.80, 0.20), "des": (1.00, 0.35),
    "document": (0.75, 0.35), "dom": (0.85, 0.45), "dsa": (1.00, 0.35),
    "ecb": (1.00, 0.35), "encode": (0.70, -1.20), "escape": (1.00, -1.90),
    "escapeshellarg": (1.10, -1.95), "escapeshellcmd": (1.10, -1.95),
    "eval": (1.20, 0.65), "exec": (1.20, 0.65), "execute": (1.05, 0.45),
    "expr": (0.60, 0.25), "filter": (0.80, -1.35), "fixed": (0.70, 0.10),
    "flag": (0.45, 0.10), "fopen": (0.85, 0.45), "form": (0.85, 0.40),
    "get": (0.75, 0.35), "getenv": (0.90, 0.45), "getparam": (0.90, 0.45),
    "hardcoded": (1.00, 0.35), "header": (0.90, 0.45), "html": (0.80, 0.40),
    "htmlentities": (1.10, -1.90), "htmlspecialchars": (1.10, -1.90),
    "http": (0.70, 0.25), "include": (1.00, 0.45), "ini": (0.55, 0.10),
    "innerhtml": (1.25, 0.65), "input": (0.90, 0.45), "intval": (1.00, -1.55),
    "javascript": (0.75, 0.25), "json": (0.70, -0.25), "key": (0.70, 0.20),
    "literal": (0.65, -0.75), "load": (0.75, 0.30), "md5": (1.10, 0.40),
    "memcpy": (1.00, 0.45), "move": (0.45, 0.05), "mysql_real_escape_string": (1.10, -1.75),
    "open": (0.80, 0.35), "param": (0.90, 0.45), "params": (0.90, 0.45),
    "parse": (0.60, -0.20), "password_hash": (1.00, -1.40), "password_verify": (1.00, -1.45),
    "path": (0.85, 0.35), "pdo": (0.75, -0.60), "php": (0.55, 0.05),
    "popen": (1.20, 0.65), "post": (0.85, 0.45), "prepare": (1.15, -2.05),
    "prepared": (1.10, -2.05), "print": (0.70, 0.25), "proc_open": (1.20, 0.65),
    "query": (0.90, 0.45), "random_bytes": (0.90, -1.50), "random_int": (0.90, -1.50),
    "raw": (1.00, 0.35), "raw_input": (0.90, 0.45), "read": (0.55, 0.15),
    "real_escape_string": (1.05, -1.75), "request": (0.95, 0.45), "requests": (0.95, 0.45),
    "require": (0.80, 0.25), "safe": (0.75, -1.25), "sanitize": (1.10, -2.10),
    "sanitized": (1.10, -2.10), "sanitizer": (1.10, -2.10), "secret": (0.75, 0.20),
    "select": (0.65, 0.20), "shell": (1.15, 0.65), "shell_exec": (1.25, 0.70),
    "sleep": (0.45, 0.05), "sql": (0.95, 0.50), "ssl": (0.80, -0.80),
    "static": (0.55, -0.15), "stmt": (0.75, -0.90), "strcat": (0.85, 0.40),
    "strcmp": (0.75, 0.10), "strcpy": (1.05, 0.55), "stream": (0.65, 0.20),
    "string": (0.60, 0.10), "strlen": (0.65, -0.10), "strncpy": (0.80, -0.45),
    "str_replace": (0.80, -0.80), "system": (1.20, 0.70), "textcontent": (1.05, -1.40),
    "tls": (0.80, -0.80), "token": (0.75, 0.20), "unserialize": (1.05, 0.55),
    "unsanitize": (0.80, 0.35), "url": (0.85, 0.35), "user": (0.75, 0.30),
    "validate": (1.00, -1.60), "validated": (1.00, -1.60), "verify": (0.95, -1.40),
    "weak": (0.80, 0.25), "whitelist": (1.00, -1.80), "write": (0.75, 0.30),
}

TOKEN_LOGIC_LAYER: Dict[str, float] = {
    "__bias__": -0.85,
    "sanitizer_near": -2.75,
    "prepared_statement": -2.55,
    "safe_dom_writer": -2.20,
    "fixed_literal": -1.30,
    "weak_crypto": 1.45,
    "hardcoded_secret": 1.35,
    "command_sink": 1.85,
    "code_sink": 1.70,
    "sql_sink": 1.55,
    "path_sink": 1.20,
    "deserialization_sink": 1.20,
    "template_sink": 1.10,
    "memory_sink": 0.75,
    "uninitialized": 0.55,
    "tainted": 1.45,
    "user_controlled": 0.85,
    "format_string": 1.20,
}

SANITIZER_TOKENS: Set[str] = {
    "absint", "addslashes", "basename", "check", "escapeshellarg", "escapeshellcmd",
    "filter", "htmlspecialchars", "htmlentities", "intval", "mysqli_real_escape_string",
    "mysql_real_escape_string", "password_hash", "password_verify", "prepare", "prepared",
    "real_escape_string", "sanitize", "sanitized", "sanitizer", "textcontent", "validate",
    "validated", "verify", "whitelist", "random_bytes", "random_int", "escape",
}
GENERIC_SANITIZER_PATTERN = re.compile(
    r"(?is)\b(?:htmlspecialchars|htmlentities|escapeshellarg|escapeshellcmd|"
    r"mysqli_real_escape_string|mysql_real_escape_string|real_escape_string|"
    r"absint|basename|intval|password_verify|textContent|createTextNode|"
    r"sanitiz(?:e|ed|er)|validat(?:e|ed|ion)|allow[-_ ]?list|white[-_ ]?list)\b"
)

SENSITIVE_SIDES = {
    "python_execution": "shell or Python execution",
    "python_code": "dynamic code execution",
    "python_sql": "SQL/database query construction",
    "python_path": "file open / include / load",
    "python_template": "HTML template rendering",
    "python_html": "HTML sink",
    "taint_exec": "shell/process/code execution",
    "taint_sql": "SQL/database query construction",
    "taint_file": "file open / include / load",
    "taint_html_dom": "HTML/DOM sink",
    "memory_risk": "memory/copy/format operation",
    "php_weak_crypto": "cryptographic primitive choice",
    "php_hardcoded_credential": "credential material",
    "password_hardcoded": "credential material",
}

SEVERITY_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

DETAILS: Dict[str, Tuple[str, str, str, str, str]] = {
    "shell or process invocation": (
        "Request/stream input or a tainted variable appears near a shell or process-launch API.",
        "If the value controls command text or unsafe process arguments, metacharacters or option-like values may alter the invoked operation; separate arguments avoid a shell parser but options can still be interpreted by the target program.",
        "In a disposable authorized test, use a benign marker and confirm it cannot add arguments or alter the selected executable; do not test against production systems.",
        "Prefer a fixed executable with an argument array and shell disabled. Validate each argument against an allow-list; avoid constructing shell command strings.",
        "high",
    ),
    "shell or Python execution": (
        "Request/stream input or a tainted variable appears near subprocess or shell-enabled execution APIs.",
        "If the value controls command text or unsafe process arguments, metacharacters or option-like values may alter the invoked operation; shell=False plus separate args avoids a shell parser but options can still be interpreted by the target program.",
        "In a disposable authorized test, use a benign marker and confirm it cannot add arguments or alter the selected executable; do not test against production systems.",
        "Prefer a fixed executable/program with an argument-array API and shell disabled. Validate each argument against an allow-list; avoid constructing shell command strings.",
        "high",
    ),
    "dynamic code execution": (
        "Runtime-controlled text or configuration flows into eval/exec-like evaluation, compilation, or template APIs.",
        "If data is treated as code or markup, unintended statements can execute in the current context. This includes some template rendering paths when templates are user-authored.",
        "In an authorized harness, supply a harmless unique marker and confirm it is neither evaluated nor able to expand template directives.",
        "Do not evaluate untrusted data. Use safe, precompiled templates, strict expression allow-lists, sandboxing, or data-only serialization; restrict available builtins and privileges.",
        "high",
    ),
    "dynamic code evaluation": (
        "Data reaches eval/exec-like evaluation APIs.",
        "If attacker-controlled, text may execute statements in the current process context.",
        "In an authorized harness, use a harmless unique marker and confirm it is not evaluated.",
        "Avoid dynamic evaluation of data; use safe expression grammars or allow-listed dispatch tables.",
        "high",
    ),
    "SQL/database query construction": (
        "Tainted or request-controlled data appears adjacent to database query construction APIs.",
        "Concatenating data into SQL can change query meaning and allow unauthorized access or updates. Even after escaping for one dialect, edge cases may remain.",
        "In a staging-only database, use a benign marker payload that would alter syntax if unbound but is inert when parameterized.",
        "Use parameterized queries/prepared statements for all values; validate inputs; enforce least-privilege database accounts.",
        "high",
    ),
    "file open / include / load": (
        "Request-controlled or variable paths reach file open/include/load-like APIs.",
        "A path or URL may point outside the intended directory, access sensitive files, expose secrets, or load unintended code; URL fetches may reach internal services.",
        "In staging, provide a harmless traversal token or internal URL and confirm the request is denied and cannot read or fetch it.",
        "Normalize and resolve paths, require them to stay under a fixed base directory, and use an allow-list of basename patterns or IDs; disable remote includes where possible.",
        "medium-high",
    ),
    "file path or trajectory sink": (
        "A variable path reaches a file open/include API.",
        "A manipulated path could target unintended files.",
        "In staging, request a benign path variant and confirm access stays below the allowed base.",
        "Use safe path resolution, a base directory, and allow-listed basenames or IDs.",
        "medium",
    ),
    "HTML/DOM sink": (
        "Request-controlled data reaches JavaScript HTML-writing or DOM mutation APIs.",
        "If data is inserted as HTML rather than text, script or markup injection may run in a victim browser.",
        "In a staging page, submit an inert unique marker and confirm it renders as text only, never as live markup or script.",
        "Use context-aware output encoding (textContent or safe template auto-escaping), sanitize HTML with a vetted allow-list, and avoid string-built HTML.",
        "high",
    ),
    "HTML template rendering": (
        "Data reaches template rendering/auto-output paths.",
        "Template output may be safe for text but unsafe for HTML or JS contexts.",
        "In staging, submit a harmless marker and confirm it stays encoded in the page context.",
        "Use auto-escaped templates and context-aware encoders.",
        "medium",
    ),
    "runtime allocation / unwind proximity": (
        "Raw allocation, pointer arithmetic/dereference, or memory-copy operations occur near a non-local error/abort/unwind path.",
        "An error jump may bypass initialization or cleanup, or carry a stale/invalid pointer across an exceptional path. This is a proximity heuristic, not proof of a runtime defect.",
        "In an authorized debug build, force the nearby allocation/error path and verify every pointer remains valid and every owned resource is released exactly once across failures.",
        "Initialize pointers, check allocation results and bounds, centralize cleanup, and avoid non-local unwinds across frames that own resources; use structured cleanup/RAII where available.",
        "medium",
    ),
    "fixed bounded allocation": (
        "A fixed-size allocation occurs near a raw copy, conversion, or error/abort path.",
        "A fixed size is not inherently unsafe; review conversion, index, and cleanup logic for off-by-one or stale-state issues.",
        "In a debug build, exercise boundary lengths and trigger induced failures to confirm no overflow, leak, or stale pointer.",
        "Bound all copies to the allocation size, validate indices, and prefer structured memory or vector/string abstractions.",
        "medium",
    ),
    "variable-size allocation": (
        "A variable-size allocation appears near pointers, casts, optional arithmetic, or an unwind/abort path.",
        "If arithmetic is unchecked, overflow/underflow can allocate too little while later copies use the intended size; a bailout can bypass cleanup.",
        "In an authorized sanitizer build, supply boundary values, force the abort, and verify allocation size, copy length, and cleanup match.",
        "Check arithmetic with safe helpers, validate ranges before allocation, and centralize failure cleanup.",
        "medium",
    ),
    "unbounded memory copy": (
        "An unbounded or commonly misused copy routine appears near pointer/buffer code.",
        "It may read/write past a destination if size and null-termination assumptions fail. This is a code-review finding, not proof of a runtime layer defect.",
        "On a sanitizer-enabled authorized build, exercise boundary-size inputs and watch for out-of-bounds access.",
        "Use bounded copies, compute sizes from the destination, and validate all lengths; prefer safe string/vector APIs.",
        "high",
    ),
    "bounded memory copy": (
        "A bounded copy appears near pointer and buffer code.",
        "The bound may still be wrong if tied to the source or an unchecked computed length.",
        "Exercise edge lengths in a sanitizer build and confirm the bound is derived from the destination capacity.",
        "Derive limits from destination capacity, validate input length, and prefer safer abstractions.",
        "medium",
    ),
    "memory format function": (
        "A format/print-style function appears near C string or buffer handling.",
        "If the format string or computed buffer size is influenced by data, information disclosure or out-of-bounds behavior may occur.",
        "In a controlled debug build, force a benign format marker and confirm the format string is compile-time fixed and output bounded.",
        "Use fixed format strings, bounded formats, and explicit size checks; never pass user data as the format.",
        "medium",
    ),
    "memory cast / arithmetic": (
        "Pointer casts or arithmetic appear near buffer/types definitions.",
        "Type confusion, truncation, or index mistakes may turn a cast into invalid access. The heuristic requires corroborating context.",
        "In a debug/fuzz harness, hit boundary values and verify all resulting pointers stay in bounds.",
        "Prefer typed APIs, explicit checked casts, and length-tracked buffers; enforce bounds at every write.",
        "medium",
    ),
    "possible uninitialized C/runtime variable": (
        "A C-like declaration without an initializer appears near allocations, branches, or abort paths.",
        "It might later be used before assignment on some path; this scanner does not build a full CFG and may miss or falsely report initialization.",
        "Enable compiler warnings and static analysis; in a debug build, force the abort or branch path to verify an initialized value is used.",
        "Initialize variables at declaration, narrow scope, and treat compiler/static-analysis warnings as failures where feasible.",
        "medium",
    ),
    "weak cryptographic primitive": (
        "MD5/SHA-1/DES/ECB-like cryptography, or static/randomly weak keys, appears in a security-sensitive context.",
        "The primitive may be collision-prone, brute-forceable, deterministic, or otherwise unsuitable for password storage or data protection.",
        "In an authorized test, attempt known test vectors or detect deterministic encryption; never target systems or data you do not own.",
        "Use modern AEAD algorithms with unique nonces/keys for confidentiality, and password_hash/password_verify (Argon2/bcrypt) for passwords.",
        "medium-high",
    ),
    "hardcoded credential material": (
        "A constant string resembling a key, secret, password, or private credential appears in code.",
        "If the value grants access, it could be exposed by source control, logs, package distribution, or reverse engineering.",
        "Rotate the value, then confirm the application reads it from a secret store and rejects the old value.",
        "Move secrets to a managed secret store, inject them at runtime, audit access, and rotate any committed values.",
        "high",
    ),
}

IDENT_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
NUMBER_RE = re.compile(r"^(?:\d+(?:\.\d+)?|0x[0-9a-fA-F]+)$")
PRINT_LOCK = threading.Lock()


def _c(name: str) -> str:
    colors = {
        "HIGH": "\033[1;31m",
        "MEDIUM": "\033[1;33m",
        "LOW": "\033[1;36m",
        "INFO": "\033[1;37m",
        "reset": "\033[0m",
        "dim": "\033[2m",
    }
    return colors.get(name, "")


def supports_ansi() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty() or os.environ.get("FORCE_COLOR") == "1"


def divider() -> str:
    return "=" * 88


def normalize_space(value: str, max_len: int = 150) -> str:
    value = re.sub(r"\s+", " ", value.replace("\x00", "\\x00")).strip()
    if len(value) <= max_len:
        return value
    return value[: max_len - 3] + "..."


def normalize_key(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()[:240]


def terminal_safe(value: object, max_len: int = 512) -> str:
    """Encode attacker-controlled text before writing it to a terminal/log.

    C0/C1 controls and Unicode format characters are converted to visible escape
    sequences so archive names, URLs, and source context cannot inject terminal
    control sequences or spoof report lines. This is output hygiene only; raw
    names are still used internally for archive lookup.
    """
    text = str(value)
    truncated = len(text) > max_len
    if truncated:
        text = text[: max(0, max_len - 3)] + "..."
    out: List[str] = []
    for ch in text:
        code = ord(ch)
        if ch == "\n":
            out.append(r"\n")
        elif ch == "\r":
            out.append(r"\r")
        elif ch == "\t":
            out.append(r"\t")
        elif ch == "\x1b":
            out.append(r"\x1b")
        elif code < 32 or code == 127 or 0x80 <= code <= 0x9F or unicodedata.category(ch) == "Cf":
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)


def token_names(text: str) -> Set[str]:
    return {t.lower() for t in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", text)}


def sanitize_score_context(text: str) -> str:
    if len(text) <= MAX_SANITIZER_SPAN:
        return text
    return text[:MAX_SANITIZER_SPAN] + text[-1024:]


def text_has_sanitizer(text: str) -> bool:
    return bool(GENERIC_SANITIZER_PATTERN.search(sanitize_score_context(text)))


def logical_sigmoid(score: float) -> float:
    # Stable logistic transform without importing math for a rare edge overflow.
    if score >= 40:
        return 1.0
    if score <= -40:
        return 0.0
    try:
        import math

        return 1.0 / (1.0 + math.exp(-score))
    except (OverflowError, ValueError):
        return 1.0 if score > 0 else 0.0


def embedded_ai_score(
    text: str,
    *,
    heuristic_label: str,
    has_taint: bool,
    sanitizer_near: bool,
    extra_positive: float = 0.0,
    extra_negative: float = 0.0,
) -> float:
    """Deterministic embedded TF-IDF + token-logic score.

    Negative sanitizer/prepared/validation terms suppress likely false positives,
    but this remains a heuristic confidence score, not an exploitability proof.
    """
    score = TF_IDF_VOCABULARY["__bias__"][1] + TOKEN_LOGIC_LAYER["__bias__"]
    tokens = token_names(text)
    for token in tokens:
        tfidf_weight, polarity = TF_IDF_VOCABULARY.get(token, (0.0, 0.0))
        if tfidf_weight:
            score += min(tfidf_weight, 1.25) * polarity * 0.55
    lower = text.lower()
    features = {key: 0.0 for key in TOKEN_LOGIC_LAYER}
    features["__bias__"] = 1.0
    if sanitizer_near:
        features["sanitizer_near"] = 1.0
        if re.search(r"(?is)(?:htmlspecialchars|htmlentities|escape|sanitiz|validat|filter|textContent|createTextNode)", text):
            features["safe_dom_writer"] = 1.0
    if re.search(r"(?is)\b(?:prepare|prepared\s+statement|executeQuery|bindParam|bindValue|setString|setInt)\b", text):
        features["prepared_statement"] = 1.0
    if re.search(r"(?is)\b(?:textContent|createTextNode|innerText)\b", text):
        features["safe_dom_writer"] = 1.0
    if re.search(r"(?is)^\s*(?:print|echo|return|printf|sprintf)?\s*['\"][^'\"]{0,160}['\"]\s*[;)]?\s*$", text.strip()):
        features["fixed_literal"] = 1.0
    label = heuristic_label.lower()
    if "weak cryptographic" in label:
        features["weak_crypto"] = 1.0
    if "credential" in label or "secret" in label:
        features["hardcoded_secret"] = 1.0
    if "shell" in label or "process" in label or "python execution" in label:
        features["command_sink"] = 1.0
    if "dynamic code" in label or "unserialize" in label or "deserialize" in label:
        features["code_sink"] = 1.0
    if "sql" in label or "database" in label:
        features["sql_sink"] = 1.0
    if "path" in label or "file" in label or "load" in label or "include" in label:
        features["path_sink"] = 1.0
    if "html" in label or "dom" in label or "template" in label:
        features["template_sink"] = 1.0
    if "memory" in label or "allocation" in label or "format function" in label:
        features["memory_sink"] = 1.0
    if "uninitialized" in label:
        features["uninitialized"] = 1.0
    if "deserialize" in label or "unserialize" in label:
        features["deserialization_sink"] = 1.0
    if has_taint:
        features["tainted"] = 1.0
        features["user_controlled"] = 1.0
    if re.search(r"(?is)\b(?:md5|sha1|des|ecb|static\s+(?:key|iv)|hardcoded)\b", lower):
        features["weak_crypto"] = max(features["weak_crypto"], 0.7)
    for feature, value in features.items():
        score += TOKEN_LOGIC_LAYER.get(feature, 0.0) * value
    score += extra_positive - extra_negative
    confidence = logical_sigmoid(score)
    return max(0.01, min(0.99, confidence))


def format_detail(label: str, fallback: str) -> Tuple[str, str, str, str, str]:
    return DETAILS.get(label, (fallback, fallback, fallback, fallback, "medium"))


@dataclass
class Finding:
    target: str
    line: int
    severity: str
    label: str
    context: str
    surface: str
    anomaly: str
    poc: str
    remediation: str
    confidence_note: str
    ai_score: Optional[float]
    source: str = "stream"


@dataclass
class ScanOptions:
    extensions: Set[str]
    read_chunk_size: int = DEFAULT_READ_CHUNK_SIZE
    max_member_bytes: int = DEFAULT_MAX_MEMBER_BYTES
    max_concurrent_files: int = DEFAULT_MAX_CONCURRENT_FILES
    min_ai_confidence: float = DEFAULT_MIN_AI_CONFIDENCE
    include_low: bool = False
    pretty_color: bool = False
    timeout_seconds: float = 30.0
    max_findings_per_target: int = 250
    verbose: bool = False
    no_s3: bool = False


StreamOpener = Callable[[], Tuple[BinaryIO, Callable[[], None]]]
FileIdentity = Tuple[int, int, int, int, int, str]


@dataclass
class ScanJob:
    """One streamable target.

    ``stream_opener`` returns a readable binary stream plus a cleanup callback.
    Archive reporters create member streams directly from the source archive (or
    an in-memory parent archive for S3/nested cases), so members are never
    materialized as files on disk or as whole-member byte strings before scan.
    ``identity`` binds local filesystem jobs to the enumerated device/inode;
    ``bounded_member`` enables the runtime archive/S3 byte limit while reading.
    """

    uri: str
    kind: str
    stream_opener: StreamOpener
    expected_size: Optional[int] = None
    origin: str = ""
    identity: Optional[FileIdentity] = None
    bounded_member: bool = False


class OutputReporter:
    def __init__(self, pretty_color: bool = False) -> None:
        self.pretty_color = pretty_color

    @staticmethod
    def _write(text: str = "") -> None:
        with PRINT_LOCK:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()

    @staticmethod
    def _write_stderr(text: str) -> None:
        with PRINT_LOCK:
            sys.stderr.write(text + "\n")
            sys.stderr.flush()

    def progress(self, message: str) -> None:
        self._write(f"[progress] {terminal_safe(message, 1000)}")

    def info(self, message: str) -> None:
        self._write(f"[info] {terminal_safe(message, 1000)}")

    def warn(self, message: str) -> None:
        self._write(f"[warn] {terminal_safe(message, 1000)}")

    def error(self, message: str) -> None:
        self._write_stderr(f"ERROR: {terminal_safe(message, 1000)}")

    def finding(self, finding: Finding) -> None:
        severity = finding.severity
        sev_color = _c(severity) if self.pretty_color else ""
        reset = _c("reset") if self.pretty_color else ""
        score = f"{finding.ai_score:.3f}" if finding.ai_score is not None else "n/a"
        lines = [
            divider(),
            f"{sev_color}[{terminal_safe(severity, 24)}]{reset} {terminal_safe(finding.label, 160)} | "
            f"{terminal_safe(finding.target, 500)}:{finding.line} | "
            f"AI Confidence Score: {score} | heuristic note: {terminal_safe(finding.confidence_note, 180)} | "
            f"source: {terminal_safe(finding.source, 80)}",
            f"Context: {terminal_safe(finding.context, 220)}",
            f"🗺️ TARGET SURFACE & DATAFLOW: {terminal_safe(finding.surface, 900)}",
            f"🚨 DETECTED LOGIC GAP ANOMALY: {terminal_safe(finding.anomaly, 900)}",
            f"💣 PROOF-OF-CONCEPT (PoC) EXPLOIT SCENARIO: {terminal_safe(finding.poc, 900)}",
            f"🛡️ STRUCTURAL CODE REMEDIATION: {terminal_safe(finding.remediation, 900)}",
            divider(),
        ]
        self._write("\n".join(lines))

    def target_done(self, target: str, bytes_read: int, lines: int, findings: int) -> None:
        self._write(
            f"[done] {terminal_safe(target, 500)}: {bytes_read} bytes, "
            f"{lines} line(s), {findings} finding(s)."
        )


class ScanError(Exception):
    pass


class TargetReader:
    """Routes files, directories, and archives to chunk-stream scan jobs.

    Local archives are opened directly. Extractable members are returned as
    ``ScanJob`` objects whose openers create member streams only when that job
    runs. Jobs therefore read decompressed data in <= configured chunk-size
    blocks and do not write extracted files to disk or retain each member as a
    complete byte string. Nested and S3 archives necessarily keep the already
    supplied parent archive bytes in memory (bounded by ``max_member_bytes``).
    """

    def __init__(self, options: ScanOptions, reporter: OutputReporter) -> None:
        self.options = options
        self.reporter = reporter

    @staticmethod
    def _looks_archive_name(name: str) -> bool:
        n = name.lower()
        return n.endswith(".zip") or n.endswith(".tar.gz") or n.endswith(".tgz") or n.endswith(".tar")

    @staticmethod
    def _matches_extension(name: str, extensions: Set[str]) -> bool:
        n = name.lower()
        base = os.path.basename(n)
        if TargetReader._looks_archive_name(base):
            return True
        _, ext = os.path.splitext(base)
        if ext in extensions:
            return True
        return any(base.endswith(e) for e in extensions)

    @staticmethod
    def _guess_kind(path: str) -> str:
        n = path.lower()
        if n.endswith(".py"):
            return "python"
        if n.endswith(".php"):
            return "php"
        if n.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
            return "javascript"
        if n.endswith(".go"):
            return "go"
        if n.endswith((".c", ".cc", ".cpp", ".h", ".hh", ".hpp", ".m", ".mm", ".rs")):
            return "c_like"
        if n.endswith(".log") or n.endswith(".txt"):
            return "log"
        return "text"

    @staticmethod
    def _identity_from_stat(st: os.stat_result, digest: str) -> FileIdentity:
        return (
            int(st.st_dev),
            int(st.st_ino),
            int(st.st_size),
            int(st.st_mtime_ns),
            int(st.st_ctime_ns),
            digest,
        )

    @staticmethod
    def _hash_open_stream(stream: BinaryIO) -> str:
        """Hash an opened regular stream using bounded blocks, then rewind it."""
        try:
            stream.seek(0)
        except (OSError, ValueError):
            pass
        digest = hashlib.sha256()
        while True:
            try:
                block = stream.read(DEFAULT_READ_CHUNK_SIZE)
            except (OSError, MemoryError) as exc:
                raise ScanError(f"failed to hash local target: {exc}") from exc
            if not block:
                break
            digest.update(block)
            del block
        try:
            stream.seek(0)
        except (OSError, ValueError) as exc:
            raise ScanError(f"failed to rewind local target after fingerprinting: {exc}") from exc
        return digest.hexdigest()

    @staticmethod
    def _open_verified_regular_stream(
        path: str,
        expected_identity: Optional[FileIdentity] = None,
    ) -> BinaryIO:
        """Open a local target without following a last-minute symlink swap.

        When expected identity is present, the opened descriptor is fingerprinted
        before it is returned. Scanning resumes from that same descriptor, so a
        pathname swap after validation cannot redirect the already opened data.
        """
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= getattr(os, "O_NOFOLLOW")
        fd: Optional[int] = None
        try:
            fd = os.open(path, flags)
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise ScanError(f"target is not a regular file at open time: {path}")
            if expected_identity is not None:
                stream = os.fdopen(fd, "rb")
                fd = None  # stream now owns the descriptor
                digest = TargetReader._hash_open_stream(stream)
                identity = TargetReader._identity_from_stat(st, digest)
                if identity != expected_identity:
                    stream.close()
                    raise ScanError(f"target changed between enumeration and open: {path}")
                return stream
            return os.fdopen(fd, "rb")
        except ScanError:
            if fd is not None:
                os.close(fd)
            raise
        except OSError as exc:
            if fd is not None:
                os.close(fd)
            raise ScanError(f"failed to open target {terminal_safe(path, 500)}: {exc.strerror or exc}") from exc

    def _identity_for_path(self, path: str) -> FileIdentity:
        stream = self._open_verified_regular_stream(path)
        try:
            st = os.fstat(stream.fileno())
            digest = self._hash_open_stream(stream)
            return self._identity_from_stat(st, digest)
        finally:
            stream.close()
            del stream

    @staticmethod
    def _regular_file_opener(
        path: str,
        expected_identity: Optional[FileIdentity] = None,
    ) -> StreamOpener:
        def open_stream() -> Tuple[BinaryIO, Callable[[], None]]:
            stream = TargetReader._open_verified_regular_stream(path, expected_identity)
            return stream, stream.close

        return open_stream

    @staticmethod
    def _bytes_opener(payload: bytes) -> StreamOpener:
        def open_stream() -> Tuple[BinaryIO, Callable[[], None]]:
            stream = io.BytesIO(payload)
            return stream, stream.close

        return open_stream

    def _zip_file_member_opener(
        self,
        archive_path: str,
        member_name: str,
        member_uri: str,
        expected_identity: Optional[FileIdentity] = None,
    ) -> StreamOpener:
        def open_stream() -> Tuple[BinaryIO, Callable[[], None]]:
            base: Optional[BinaryIO] = None
            archive: Optional[zipfile.ZipFile] = None
            stream: Optional[BinaryIO] = None
            try:
                base = self._open_verified_regular_stream(archive_path, expected_identity)
                archive = zipfile.ZipFile(base, mode="r")
                info = archive.getinfo(member_name)
                if info.file_size > self.options.max_member_bytes:
                    raise ScanError(
                        f"ZIP member {member_uri} is {info.file_size} bytes; limit is {self.options.max_member_bytes}"
                    )
                stream = archive.open(info, mode="r")

                def close_stream() -> None:
                    try:
                        if stream is not None:
                            stream.close()
                    finally:
                        try:
                            if archive is not None:
                                archive.close()
                        finally:
                            if base is not None:
                                base.close()

                return stream, close_stream
            except ScanError:
                if archive is not None:
                    archive.close()
                if base is not None:
                    base.close()
                raise
            except (KeyError, RuntimeError, zipfile.BadZipFile, NotImplementedError, OSError, ValueError) as exc:
                if archive is not None:
                    archive.close()
                if base is not None:
                    base.close()
                raise ScanError(f"ZIP member unreadable {member_uri}: {exc}") from exc

        return open_stream

    def _zip_bytes_member_opener(self, payload: bytes, member_name: str, member_uri: str) -> StreamOpener:
        def open_stream() -> Tuple[BinaryIO, Callable[[], None]]:
            base: Optional[io.BytesIO] = None
            archive: Optional[zipfile.ZipFile] = None
            stream: Optional[BinaryIO] = None
            try:
                base = io.BytesIO(payload)
                archive = zipfile.ZipFile(base, mode="r")
                info = archive.getinfo(member_name)
                if info.file_size > self.options.max_member_bytes:
                    raise ScanError(
                        f"ZIP member {member_uri} is {info.file_size} bytes; limit is {self.options.max_member_bytes}"
                    )
                stream = archive.open(info, mode="r")

                def close_stream() -> None:
                    try:
                        if stream is not None:
                            stream.close()
                    finally:
                        try:
                            if archive is not None:
                                archive.close()
                        finally:
                            if base is not None:
                                base.close()

                return stream, close_stream
            except ScanError:
                if archive is not None:
                    archive.close()
                if base is not None:
                    base.close()
                raise
            except (KeyError, RuntimeError, zipfile.BadZipFile, NotImplementedError, OSError, ValueError) as exc:
                if archive is not None:
                    archive.close()
                if base is not None:
                    base.close()
                raise ScanError(f"ZIP member unreadable {member_uri}: {exc}") from exc

        return open_stream

    def _tar_file_member_opener(
        self,
        archive_path: str,
        member_name: str,
        member_uri: str,
        mode: str,
        expected_identity: Optional[FileIdentity] = None,
    ) -> StreamOpener:
        def open_stream() -> Tuple[BinaryIO, Callable[[], None]]:
            base: Optional[BinaryIO] = None
            archive: Optional[tarfile.TarFile] = None
            stream: Optional[BinaryIO] = None
            try:
                base = self._open_verified_regular_stream(archive_path, expected_identity)
                archive = tarfile.open(fileobj=base, mode=mode)
                member = archive.getmember(member_name)
                if member.size > self.options.max_member_bytes:
                    raise ScanError(
                        f"TAR member {member_uri} is {member.size} bytes; limit is {self.options.max_member_bytes}"
                    )
                stream = archive.extractfile(member)
                if stream is None:
                    raise ScanError(f"TAR member has no readable file stream: {member_uri}")

                def close_stream() -> None:
                    try:
                        if stream is not None:
                            stream.close()
                    finally:
                        try:
                            if archive is not None:
                                archive.close()
                        finally:
                            if base is not None:
                                base.close()

                return stream, close_stream
            except ScanError:
                if archive is not None:
                    archive.close()
                if base is not None:
                    base.close()
                raise
            except (KeyError, tarfile.TarError, OSError, RuntimeError, ValueError) as exc:
                if archive is not None:
                    archive.close()
                if base is not None:
                    base.close()
                raise ScanError(f"TAR member unreadable {member_uri}: {exc}") from exc

        return open_stream

    def _tar_bytes_member_opener(self, payload: bytes, member_name: str, member_uri: str, mode: str) -> StreamOpener:
        def open_stream() -> Tuple[BinaryIO, Callable[[], None]]:
            base: Optional[io.BytesIO] = None
            archive: Optional[tarfile.TarFile] = None
            stream: Optional[BinaryIO] = None
            try:
                base = io.BytesIO(payload)
                archive = tarfile.open(fileobj=base, mode=mode)
                member = archive.getmember(member_name)
                if member.size > self.options.max_member_bytes:
                    raise ScanError(
                        f"TAR member {member_uri} is {member.size} bytes; limit is {self.options.max_member_bytes}"
                    )
                stream = archive.extractfile(member)
                if stream is None:
                    raise ScanError(f"TAR member has no readable file stream: {member_uri}")

                def close_stream() -> None:
                    try:
                        if stream is not None:
                            stream.close()
                    finally:
                        try:
                            if archive is not None:
                                archive.close()
                        finally:
                            if base is not None:
                                base.close()

                return stream, close_stream
            except ScanError:
                if archive is not None:
                    archive.close()
                if base is not None:
                    base.close()
                raise
            except (KeyError, tarfile.TarError, OSError, RuntimeError, ValueError) as exc:
                if archive is not None:
                    archive.close()
                if base is not None:
                    base.close()
                raise ScanError(f"TAR member unreadable {member_uri}: {exc}") from exc

        return open_stream

    def _read_nested_payload(self, stream: BinaryIO, member_uri: str) -> bytes:
        """Read a nested archive payload, bounded by max_member_bytes.

        This is used only when the member itself is another archive that must be
        inspected. Leaf members are streamed directly and never pass through
        this whole-payload path.
        """
        parts: List[bytes] = []
        total = 0
        limit = self.options.max_member_bytes
        try:
            while True:
                request = min(self.options.read_chunk_size, limit + 1 - total)
                if request <= 0:
                    raise ScanError(f"nested archive exceeds {limit} bytes: {member_uri}")
                chunk_data = stream.read(request)
                if not chunk_data:
                    break
                total += len(chunk_data)
                if total > limit:
                    del chunk_data
                    raise ScanError(f"nested archive exceeds {limit} bytes: {member_uri}")
                parts.append(chunk_data)
                del chunk_data
            payload = b"".join(parts)
            for part in parts:
                del part
            del parts
            return payload
        except (OSError, MemoryError, tarfile.TarError, zipfile.BadZipFile, RuntimeError, ValueError) as exc:
            raise ScanError(f"nested archive member unreadable {member_uri}: {exc}") from exc

    @staticmethod
    def _tar_mode(uri: str) -> str:
        return "r:gz" if uri.lower().endswith((".tar.gz", ".tgz")) else "r:*"

    def iter_blob_jobs(self, uri: str, payload: bytes, depth: int = 0) -> Iterator[ScanJob]:
        """Yield jobs for an object already present in memory (S3/nested)."""
        name = uri.lower()
        if name.endswith(".zip"):
            yield from self._iter_zip_bytes_jobs(uri, payload, depth)
        elif name.endswith((".tar.gz", ".tgz", ".tar")):
            yield from self._iter_tar_bytes_jobs(uri, payload, depth)
        else:
            yield ScanJob(
                uri,
                self._guess_kind(uri),
                self._bytes_opener(payload),
                len(payload),
                uri,
                bounded_member=True,
            )

    def iter_archive_file_jobs(
        self,
        path: str,
        expected_identity: Optional[FileIdentity] = None,
    ) -> Iterator[ScanJob]:
        name = path.lower()
        if name.endswith(".zip"):
            yield from self._iter_zip_file_jobs(path, expected_identity)
        elif name.endswith((".tar.gz", ".tgz", ".tar")):
            yield from self._iter_tar_file_jobs(path, expected_identity)

    def _walk_nested(self, member_uri: str, payload: bytes, depth: int) -> Iterator[ScanJob]:
        if depth > 3:
            self.reporter.warn(f"skipping nested archive beyond depth 3: {member_uri}")
            return
        try:
            yield from self.iter_blob_jobs(member_uri, payload, depth)
        except (tarfile.TarError, zipfile.BadZipFile, OSError, ValueError, RuntimeError) as exc:
            self.reporter.error(f"nested archive unreadable {member_uri}: {exc}")

    def _iter_zip_file_jobs(
        self,
        path: str,
        expected_identity: Optional[FileIdentity] = None,
    ) -> Iterator[ScanJob]:
        base: Optional[BinaryIO] = None
        try:
            base = self._open_verified_regular_stream(path, expected_identity)
            with zipfile.ZipFile(base, mode="r") as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    member_name = info.filename
                    if not self._matches_extension(member_name, self.options.extensions):
                        continue
                    member_uri = f"{path}!{member_name}"
                    if info.file_size > self.options.max_member_bytes:
                        self.reporter.warn(
                            f"skipping oversized ZIP member {member_name!r} ({info.file_size} bytes) in {path}"
                        )
                        continue
                    if self._looks_archive_name(member_name):
                        stream = archive.open(info, mode="r")
                        try:
                            payload = self._read_nested_payload(stream, member_uri)
                        finally:
                            stream.close()
                        yield from self._walk_nested(member_uri, payload, 1)
                        del payload
                    else:
                        yield ScanJob(
                            member_uri,
                            self._guess_kind(member_name),
                            self._zip_file_member_opener(path, member_name, member_uri, expected_identity),
                            info.file_size,
                            path,
                            expected_identity,
                            True,
                        )
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError) as exc:
            self.reporter.error(f"corrupt or unsupported ZIP target {path}: {exc}")
        except ScanError as exc:
            self.reporter.error(str(exc))
        finally:
            if base is not None:
                base.close()
            del base
            gc.collect()

    def _iter_zip_bytes_jobs(self, uri: str, payload: bytes, depth: int) -> Iterator[ScanJob]:
        try:
            with zipfile.ZipFile(io.BytesIO(payload), mode="r") as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    member_name = info.filename
                    if not self._matches_extension(member_name, self.options.extensions):
                        continue
                    member_uri = f"{uri}!{member_name}"
                    if info.file_size > self.options.max_member_bytes:
                        self.reporter.warn(
                            f"skipping oversized ZIP member {member_name!r} ({info.file_size} bytes) in {uri}"
                        )
                        continue
                    if self._looks_archive_name(member_name):
                        stream = archive.open(info, mode="r")
                        try:
                            nested = self._read_nested_payload(stream, member_uri)
                        finally:
                            stream.close()
                        yield from self._walk_nested(member_uri, nested, depth + 1)
                        del nested
                    else:
                        yield ScanJob(
                            member_uri,
                            self._guess_kind(member_name),
                            self._zip_bytes_member_opener(payload, member_name, member_uri),
                            info.file_size,
                            uri,
                            bounded_member=True,
                        )
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError) as exc:
            self.reporter.error(f"corrupt or unsupported ZIP target {uri}: {exc}")
        except ScanError as exc:
            self.reporter.error(str(exc))

    def _iter_tar_file_jobs(
        self,
        path: str,
        expected_identity: Optional[FileIdentity] = None,
    ) -> Iterator[ScanJob]:
        mode = self._tar_mode(path)
        base: Optional[BinaryIO] = None
        try:
            base = self._open_verified_regular_stream(path, expected_identity)
            with tarfile.open(fileobj=base, mode=mode) as archive:
                for member in archive:
                    if not member.isfile():
                        continue
                    member_name = member.name
                    if not self._matches_extension(member_name, self.options.extensions):
                        continue
                    member_uri = f"{path}!{member_name}"
                    if member.size > self.options.max_member_bytes:
                        self.reporter.warn(
                            f"skipping oversized TAR member {member_name!r} ({member.size} bytes) in {path}"
                        )
                        continue
                    if self._looks_archive_name(member_name):
                        stream = archive.extractfile(member)
                        if stream is None:
                            self.reporter.error(f"TAR member has no readable file stream: {member_uri}")
                            continue
                        try:
                            payload = self._read_nested_payload(stream, member_uri)
                        finally:
                            stream.close()
                        yield from self._walk_nested(member_uri, payload, 1)
                        del payload
                    else:
                        yield ScanJob(
                            member_uri,
                            self._guess_kind(member_name),
                            self._tar_file_member_opener(
                                path,
                                member_name,
                                member_uri,
                                mode,
                                expected_identity,
                            ),
                            member.size,
                            path,
                            expected_identity,
                            True,
                        )
        except (tarfile.TarError, OSError, ValueError, RuntimeError) as exc:
            self.reporter.error(f"corrupt or unsupported TAR target {path}: {exc}")
        except ScanError as exc:
            self.reporter.error(str(exc))
        finally:
            if base is not None:
                base.close()
            del base
            gc.collect()

    def _iter_tar_bytes_jobs(self, uri: str, payload: bytes, depth: int) -> Iterator[ScanJob]:
        mode = self._tar_mode(uri)
        try:
            with tarfile.open(fileobj=io.BytesIO(payload), mode=mode) as archive:
                for member in archive:
                    if not member.isfile():
                        continue
                    member_name = member.name
                    if not self._matches_extension(member_name, self.options.extensions):
                        continue
                    member_uri = f"{uri}!{member_name}"
                    if member.size > self.options.max_member_bytes:
                        self.reporter.warn(
                            f"skipping oversized TAR member {member_name!r} ({member.size} bytes) in {uri}"
                        )
                        continue
                    if self._looks_archive_name(member_name):
                        stream = archive.extractfile(member)
                        if stream is None:
                            self.reporter.error(f"TAR member has no readable file stream: {member_uri}")
                            continue
                        try:
                            nested = self._read_nested_payload(stream, member_uri)
                        finally:
                            stream.close()
                        yield from self._walk_nested(member_uri, nested, depth + 1)
                        del nested
                    else:
                        yield ScanJob(
                            member_uri,
                            self._guess_kind(member_name),
                            self._tar_bytes_member_opener(payload, member_name, member_uri, mode),
                            member.size,
                            uri,
                            bounded_member=True,
                        )
        except (tarfile.TarError, OSError, ValueError, RuntimeError) as exc:
            self.reporter.error(f"corrupt or unsupported TAR target {uri}: {exc}")
        except ScanError as exc:
            self.reporter.error(str(exc))

    def list_local_jobs(self, path: str) -> Iterator[ScanJob]:
        if os.path.islink(path):
            raise ScanError(f"refusing symlink target: {path}")
        try:
            st = os.stat(path)
        except OSError as exc:
            raise ScanError(f"target path missing or unreadable: {path}: {exc.strerror or exc}") from exc
        if stat.S_ISDIR(st.st_mode):
            for root, dirs, files in os.walk(path, topdown=True, onerror=None, followlinks=False):
                dirs[:] = [
                    d for d in dirs
                    if d not in {".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv", "venv"}
                ]
                for filename in files:
                    full = os.path.join(root, filename)
                    if not self._matches_extension(full, self.options.extensions):
                        continue
                    if os.path.islink(full):
                        continue
                    try:
                        item_stat = os.stat(full)
                    except OSError as exc:
                        self.reporter.error(f"target skipped; stat failed {full}: {exc.strerror or exc}")
                        continue
                    if not stat.S_ISREG(item_stat.st_mode):
                        continue
                    identity = self._identity_for_path(full)
                    if self._looks_archive_name(full):
                        yield from self.iter_archive_file_jobs(full, identity)
                    else:
                        yield ScanJob(
                            full,
                            self._guess_kind(full),
                            self._regular_file_opener(full, identity),
                            item_stat.st_size,
                            path,
                            identity,
                        )
            return
        if not stat.S_ISREG(st.st_mode):
            raise ScanError(f"target is not a regular file or directory: {path}")
        identity = self._identity_for_path(path)
        if self._looks_archive_name(path):
            yield from self.iter_archive_file_jobs(path, identity)
            return
        yield ScanJob(
            path,
            self._guess_kind(path),
            self._regular_file_opener(path, identity),
            st.st_size,
            path,
            identity,
        )

# ----------------------------- S3 streaming layer -----------------------------

class _NoCredentialForwardingRedirect(urllib.request.HTTPRedirectHandler):
    """Fail closed on redirects before signed headers can cross origins."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoCredentialForwardingRedirect())


def _hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _quote(value: str, safe: str = "") -> str:
    return urllib.parse.quote(value, safe=safe)


def _build_s3_url(bucket: str, key: str, endpoint: Optional[str]) -> str:
    if not endpoint:
        endpoint = os.environ.get("AWS_ENDPOINT_URL_S3", "http://127.0.0.1:4566")
    endpoint = endpoint.rstrip("/")
    bucket_enc = _quote(bucket)
    key_enc = "/".join(_quote(part) for part in key.split("/"))
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        return f"{endpoint}/{bucket_enc}/{key_enc}"
    return f"https://{endpoint}/{bucket_enc}/{key_enc}"


def _aws_sigv4_headers(
    method: str,
    url: str,
    region: str,
    service: str = "s3",
    payload_sha256: Optional[str] = None,
) -> Dict[str, str]:
    access = os.environ.get("AWS_ACCESS_KEY_ID")
    secret = os.environ.get("AWS_SECRET_ACCESS_KEY")
    token = os.environ.get("AWS_SESSION_TOKEN")
    if not access or not secret:
        return {}
    parsed = urllib.parse.urlsplit(url)
    host = parsed.netloc
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = payload_sha256 or _sha256_hex(b"")
    headers = {
        "host": host,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
    }
    if token:
        headers["x-amz-security-token"] = token
    canonical_uri = parsed.path or "/"
    canonical_query = parsed.query
    canonical_headers = "".join(f"{k}:{v}\n" for k, v in sorted(headers.items()))
    signed_headers = ";".join(sorted(headers))
    canonical_request = "\n".join([
        method,
        canonical_uri,
        canonical_query,
        canonical_headers,
        signed_headers,
        payload_hash,
    ])
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])
    k_date = _hmac_sha256(("AWS4" + secret).encode("utf-8"), date_stamp)
    k_region = _hmac_sha256(k_date, region)
    k_service = _hmac_sha256(k_region, service)
    k_signing = _hmac_sha256(k_service, "aws4_request")
    signature = _hmac_sha256(k_signing, string_to_sign).hex()
    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
    return headers


def fetch_s3_to_memory(options: ScanOptions, reporter: OutputReporter, bucket: str, key: str, region: Optional[str]) -> bytes:
    if options.no_s3:
        raise ScanError("S3 flags were provided, but --no-s3 is set; refusing outbound network access.")
    url = _build_s3_url(bucket, key, None)
    reporter.info(f"opening read-only S3 stream: {url}")
    headers = {"User-Agent": f"disk-stream-scanner/{VERSION}"}
    default_region = region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
    headers.update(_aws_sigv4_headers("GET", url, default_region, payload_sha256=_sha256_hex(b"")))
    request = urllib.request.Request(url, headers=headers, method="GET")
    chunks: List[bytes] = []
    total = 0
    try:
        with _NO_REDIRECT_OPENER.open(request, timeout=options.timeout_seconds) as response:  # nosec B310 - user-selected-object read
            status = getattr(response, "status", 200)
            if status and status >= 400:
                raise ScanError(f"S3 endpoint returned HTTP {status}")
            while True:
                part = response.read(options.read_chunk_size)
                if not part:
                    break
                total += len(part)
                if total > options.max_member_bytes:
                    raise ScanError(f"S3 object exceeds configured embedded limit of {options.max_member_bytes} bytes.")
                chunks.append(part)
                reporter.progress(f"S3 streamed {total} bytes from {bucket}/{key}")
                del part
                if len(chunks) % 8 == 0:
                    gc.collect()
    except urllib.error.URLError as exc:
        raise ScanError(f"failed to stream S3 object {bucket}/{key}: {exc}") from exc
    data = b"".join(chunks)
    for part in chunks:
        del part
    del chunks
    gc.collect()
    reporter.progress(f"S3 object buffered for local scanning ({total} bytes).")
    return data


# ----------------------------- Logical scanner core -----------------------------

class LogicalScanner:
    """Sliding-window lexical scanner plus whole-buffer heuristic classifier."""

    SOURCE_RE = re.compile(
        r"(?is)(\$_(?:get|post|request|cookie|files|server)\s*(?:\[[^\]]+\])?|"
        r"\b(?:document\.(?:getElementById|querySelector|location|URLSearchParams)|"
        r"location\.(?:search|hash)|window\.location|process\.argv|os\.environ|os\.getenv|"
        r"getenv|raw_input|input\s*\(|sys\.argv|stdin|readline|fgets|gets|"
        r"\b(?:request|requests)\.(?:GET|POST|REQUEST|args|form|values|cookies|headers|query_params|data|json|body)\b|"
        r"\b(?:req|request|params|query|body|cookies|headers|payload|arg|argv|argc|input|filename|filepath|path)\b))"
    )
    DUMP_RE = re.compile(r"(?is)\b(?:var_dump|print_r|var_export)\b")
    ESCAPE_RE = SANITIZER_TOKENS

    EXEC_SINKS = re.compile(
        r"(?is)\b(?:system|shell_exec|exec|popen|proc_open|passthru|pcntl_exec|subprocess\.(?:run|Popen|call|check_output)|"
        r"os\.(?:system|popen)|commands\.getoutput|Runtime\.getRuntime\(\)\.exec)\s*\(|"
        r"\b(?:eval|assert|create_function)\s*\("
    )
    SQL_SINKS = re.compile(
        r"(?is)\b(?:mysql_query|mysqli_query|sqlite_query|pg_query|query|execute|executemany|rawQuery|execQuery|executeQuery)\s*\(|"
        r"\b(?:SELECT|INSERT|UPDATE|DELETE|REPLACE|UNION|WHERE)\b.*\b(?:FROM|INTO|SET)\b"
    )
    FILE_SINKS = re.compile(
        r"(?is)\b(?:include|include_once|require|require_once|file_get_contents|fopen|readfile|open|load|download|import)\s*\("
    )
    HTML_SINKS = re.compile(
        r"(?is)(\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|insertAdjacentHTML\s*\(|"
        r"\b(?:echo|print|printf)\b|\brender(?:Template|String)?\s*\()"
    )
    UNWIND_RE = re.compile(
        r"(?is)\b(?:zend_bailout|longjmp|_longjmp|siglongjmp|setjmp\s*\([^)]*\)\s*&&|abort\s*\(|exit\s*\(|"
        r"throw\s+[^;]+|panic\s*\(|goto\s+\w+)\b"
    )
    ALLOCATION_RE = re.compile(
        r"(?is)\b(?:malloc|calloc|realloc|free|emalloc|efree|pemalloc|pefree|safe_emalloc|"
        r"new\s+(?:char|unsigned\s+char|int|byte)|std::vector<[^>]+>|make_unique|make_shared)\b"
    )
    MEMORY_OP_RE = re.compile(
        r"(?is)\b(?:memcpy|memmove|strcpy|strcat|strncpy|strncat|sprintf|vsprintf|snprintf|printf|fprintf)\b|"
        r"(?:^|[^\w])(?:\*|->|\.)\s*[A-Za-z_$][A-Za-z0-9_$]*\s*(?:[+\-*/]?=|\[[^\]]+\])"
    )
    UNINITIALIZED_RE = re.compile(
        r"^\s*(?:zend_(?:char|string|long|double|bool)|char(?:\s+const)?\s*\*?|unsigned\s+char\s*\*?|int|long|size_t|ssize_t|"
        r"zend_bool|zend_string\s*\*?|zval\s*\*?)\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*(?:;\s*)$"
    )
    ASSIGN_RE = re.compile(
        r"^\s*(?:\$|var\s+|let\s+|const\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(.+?)\s*;?\s*$"
    )
    POINTER_DECL_RE = re.compile(
        r"^\s*(?:zend_char|zend_string|zend_long|char\s*const|char|unsigned\s+char|int|long|size_t|zend_bool|zval)\s*\*?\s*"
        r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[\s*\d+\s*\])?\s*(?:=\s*(.+?))?;\s*$"
    )
    SINK_ARG_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")

    def __init__(self, target_display: str, options: ScanOptions, reporter: OutputReporter) -> None:
        self.target_display = target_display
        self.options = options
        self.reporter = reporter
        self.line_number = 0
        self.pending = bytearray()
        self.line_fragmented = False
        self.vars_tainted: Set[str] = set()
        self.vars_sanitized: Set[str] = set()
        self.declared_uninitialized: Set[str] = set()
        self.pointer_vars: Set[str] = set()
        self.numeric_alloc_sizes: Set[Tuple[str, str]] = set()
        self.recent_lines: Deque[Tuple[int, str]] = deque(maxlen=5)
        self.recent_alloc_warnings: Deque[Tuple[int, str, str]] = deque(maxlen=5)
        self.findings_seen: Set[str] = set()
        self.bytes_read = 0
        self.records_scanned = 0
        self.findings = 0
        self.limit_reached = False

    def feed(self, chunk_data: bytes) -> None:
        if self.limit_reached:
            return
        self.bytes_read += len(chunk_data)
        start = 0
        data_len = len(chunk_data)
        while True:
            idx = chunk_data.find(b"\n", start)
            if idx == -1:
                if start < data_len:
                    self._append_pending(chunk_data[start:])
                break
            self._append_pending(chunk_data[start : idx + 1])
            self._finish_physical_line()
            start = idx + 1
        if len(self.pending) > MAX_PENDING_LINE_BYTES:
            self._drop_pending("pending non-newline stream exceeded the bounded 8 MiB line window")

    def _append_pending(self, data: bytes) -> None:
        if not data:
            return
        if len(self.pending) + len(data) <= MAX_PHYSICAL_LINE_BYTES:
            self.pending.extend(data)
            return

        # Keep only a bounded head/tail and never concatenate the full
        # oversized line. This prevents a 100 MiB read block from becoming a
        # second transient copy when a newline is absent.
        marker = b" [... omitted mid-line bytes ...] "
        keep_total = max(0, MAX_PHYSICAL_LINE_BYTES - len(marker))
        head_len = keep_total // 2
        tail_len = keep_total - head_len

        head_pending = bytes(self.pending[:head_len])
        head: bytes
        tail: bytes
        if len(head_pending) < head_len:
            head_needed = head_len - len(head_pending)
            head = head_pending + bytes(data[:head_needed])
        else:
            head = head_pending

        if len(data) >= tail_len:
            tail = bytes(data[-tail_len:]) if tail_len else b""
        else:
            tail_needed_from_pending = tail_len - len(data)
            pending_start = max(0, len(self.pending) - tail_needed_from_pending)
            tail = bytes(self.pending[pending_start:]) + data

        del head_pending
        self.pending = bytearray(head + marker + tail)
        del head, tail
        self.line_fragmented = True
        gc.collect()

    def _drop_pending(self, message: str) -> None:
        self.reporter.warn(f"{message}; dropping buffered fragment at {self.target_display}")
        self.pending.clear()
        self.line_fragmented = True

    def _finish_physical_line(self, force_empty: bool = False) -> None:
        if self.limit_reached:
            return
        raw = bytes(self.pending)
        self.pending.clear()
        self.line_number += 1
        if raw.endswith(b"\n"):
            raw = raw[:-1]
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if not raw and not force_empty:
            self._clear_transient_line_state()
            return
        try:
            scan = raw.decode("utf-8", errors="replace")
        except (UnicodeDecodeError, ValueError, MemoryError):
            scan = raw.decode("latin-1", errors="replace")
        self._process_record(scan, self.line_number, is_fragment=self.line_fragmented)
        self.line_fragmented = False
        self._clear_transient_line_state()

    def _clear_transient_line_state(self) -> None:
        pass

    def _report(
        self,
        label: str,
        severity: str,
        line_number: int,
        context: str,
        surface: str,
        anomaly: str,
        poc: str,
        remediation: str,
        confidence_note: str,
        ai_score: Optional[float],
        *,
        dedupe_extra: str = "",
    ) -> None:
        context_clean = normalize_space(context, 150)
        key = (
            f"{severity}|{label}|{line_number}|"
            f"{normalize_key(context_clean)}|{normalize_space(dedupe_extra, 80)}"
        )
        if key in self.findings_seen:
            return
        if self.findings >= self.options.max_findings_per_target:
            self.limit_reached = True
            self.reporter.warn(f"finding limit for {self.target_display} reached; further candidates suppressed.")
            return
        self.findings_seen.add(key)
        self.findings += 1
        finding = Finding(
            target=self.target_display,
            line=line_number,
            severity=severity,
            label=label,
            context=context_clean,
            surface=surface,
            anomaly=anomaly,
            poc=poc,
            remediation=remediation,
            confidence_note=confidence_note,
            ai_score=ai_score,
            source="ast+lexical",
        )
        self.reporter.finding(finding)

    @staticmethod
    def _strip_line_comment(line: str) -> str:
        for marker in ("//", "#"):
            idx = line.find(marker)
            if idx == 0:
                return line[:idx]
        stripped = line.lstrip()
        if stripped.startswith(("//", "#", "*", "/*")):
            return ""
        return line

    @staticmethod
    def _is_fixed_literal_expr(expr: str) -> bool:
        stripped = expr.strip()
        return bool(
            NUMBER_RE.match(stripped)
            or re.fullmatch(r"[-+]?\d+(?:\.\d+)?", stripped)
            or re.fullmatch(r"['\"][^'\"]{0,160}['\"]", stripped)
        )

    def _expr_contains_taint(self, expr: str) -> bool:
        tokens = token_names(expr)
        if "$_get" in expr.lower() or "$_post" in expr.lower() or "$_request" in expr.lower() or "$_cookie" in expr.lower():
            return True
        if self.SOURCE_RE.search(expr):
            return True
        for var in self.vars_tainted:
            if var in tokens or f"${var}" in expr.lower():
                return True
        return False

    def _expr_has_sanitizer(self, expr: str) -> bool:
        return text_has_sanitizer(expr)

    def _window_text(self, line_number: int, current: str, span: int = 2) -> str:
        parts = [text for num, text in self.recent_lines if line_number - span <= num < line_number]
        parts.append(current)
        return "\n".join(parts)

    def _update_assignment_state(self, line: str) -> None:
        m = self.ASSIGN_RE.match(line)
        if not m:
            return
        name, expr = m.group(1), m.group(2)
        if not IDENT_RE.match(name):
            return
        if self._expr_contains_taint(expr) and not self.DUMP_RE.search(expr):
            self.vars_tainted.add(name)
        elif re.search(r"\b(?:NULL|nullptr|None)\b", expr):
            self.vars_tainted.discard(name)
        elif self._expr_has_sanitizer(expr):
            self.vars_sanitized.add(name)
            self.vars_tainted.discard(name)
        elif re.search(r"\$?([A-Za-z_$][A-Za-z0-9_$]*)", expr) and not self._expr_contains_taint(expr):
            tokens = token_names(expr)
            if tokens & self.vars_tainted:
                self.vars_tainted.add(name)
        if self._expr_has_sanitizer(expr):
            self.vars_sanitized.add(name)
        if self.POINTER_DECL_RE.match(line) is None and re.search(r"\s\*", expr):
            self.pointer_vars.add(name)

    def _check_uninitialized(self, line: str, line_number: int) -> None:
        m = self.UNINITIALIZED_RE.match(line)
        if m:
            name = m.group(1)
            self.declared_uninitialized.add(name)
        else:
            init_match = re.match(
                r"^\s*(?:zend_(?:char|string|long|double|bool)|char(?:\s+const)?\s*\*?|unsigned\s+char\s*\*?|int|long|size_t|ssize_t|zend_bool|zend_string\s*\*|zval\s*\*)\s*"
                r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=\s*[^;]+)?;",
                line,
            )
            if init_match and "=" in line:
                self.declared_uninitialized.discard(init_match.group(1))
        assign = self.ASSIGN_RE.match(line)
        if assign:
            name = assign.group(1)
            self.declared_uninitialized.discard(name)
            expr = assign.group(2)
            if re.search(rf"\b(?:{re.escape(name)})\b\s*(?:[+\-*/]|\||&)", expr):
                if name not in self.vars_tainted and name not in self.vars_sanitized:
                    if name in self.declared_uninitialized or re.match(r"^\s*int\s+" + re.escape(name) + r"\s*;", "\n".join(t for _, t in self.recent_lines)):
                        score = embedded_ai_score(line, heuristic_label="possible uninitialized C/runtime variable", has_taint=False, sanitizer_near=False)
                        surface, anomaly, poc, remediation, note = format_detail("possible uninitialized C/runtime variable", "Heuristic uninitialized variable finding")
                        self._report(
                            "possible uninitialized C/runtime variable",
                            "MEDIUM", line_number, line, surface, anomaly, poc, remediation,
                            "low (syntax and control flow are not parsed)", score,
                        )
        num_alloc = re.search(
            r"(?is)\b(?:emalloc|malloc|safe_emalloc|pemalloc)\s*\(\s*(?:\(\s*size_t\s*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:[+\-*/][^;)]*)?\)",
            line,
        )
        if num_alloc:
            var = num_alloc.group(1)
            window = self._window_text(line_number, line, span=3)
            if var in self.declared_uninitialized or (var not in self.vars_tainted and var not in self.vars_sanitized and not re.search(rf"\b{re.escape(var)}\s*=", window)):
                if not re.search(rf"\b{re.escape(var)}\s*=", window):
                    text = f"variable-size allocation using {var}: {line}"
                    score = embedded_ai_score(text, heuristic_label="possible uninitialized C/runtime variable", has_taint=False, sanitizer_near=False)
                    surface, anomaly, poc, remediation, note = format_detail("possible uninitialized C/runtime variable", "Heuristic uninitialized variable finding")
                    self._report(
                        "possible uninitialized C/runtime variable",
                        "MEDIUM", line_number, line,
                        "An allocation size variable appears before any observed assignment in the bounded scan window.",
                        "If no earlier out-of-window assignment initialized it, the allocation could use an indeterminate value. Adaptive slicing and full-file context may miss initializers.",
                        "Compile with warnings and use a debug/sanitizer build to verify the value is initialized before the allocation.",
                        "Initialize allocation-size variables before use and enable -Wuninitialized/-Wmaybe-uninitialized in CI.",
                        "low (line-window heuristic)", score,
                    )
        alloc_fixed = re.search(r"(?is)\b(?:emalloc|malloc|safe_emalloc|pemalloc)\s*\(\s*(\d+)\s*\)", line)
        if alloc_fixed:
            self.numeric_alloc_sizes.add((alloc_fixed.group(1), line.strip()))
        if self.UNWIND_RE.search(line):
            self._check_runtime_unwind(line, line_number)

    def _check_runtime_unwind(self, line: str, line_number: int) -> None:
        window_lines = [(n, t) for n, t in self.recent_lines if line_number - 4 <= n <= line_number]
        window_lines.append((line_number, line))
        window_text = "\n".join(t for _, t in window_lines)
        if not (self.ALLOCATION_RE.search(window_text) or self.MEMORY_OP_RE.search(window_text) or self.pointer_vars):
            return
        sanitizer_near = text_has_sanitizer(window_text)
        has_taint = self._expr_contains_taint(window_text)
        score = embedded_ai_score(
            sanitize_score_context(window_text),
            heuristic_label="runtime allocation / unwind proximity",
            has_taint=has_taint,
            sanitizer_near=sanitizer_near,
        )
        surface, anomaly, poc, remediation, note = format_detail("runtime allocation / unwind proximity", "Runtime allocation near an unwind path")
        self._report(
            "runtime allocation / unwind proximity",
            "MEDIUM", line_number, line,
            surface,
            anomaly,
            poc,
            remediation + " This analysis is lexical; confirm with compiler warnings, ASan/Valgrind, and manual path review.",
            "low-to-medium (bounded line-window heuristic)", score,
        )

    def _check_memory(self, line: str, line_number: int) -> None:
        if not self.MEMORY_OP_RE.search(line) and not self.ALLOCATION_RE.search(line):
            return
        window_text = self._window_text(line_number, line, span=2)
        sanitizer_near = text_has_sanitizer(window_text)
        has_taint = self._expr_contains_taint(window_text)
        if re.search(r"(?is)\b(?:strcpy|strcat|gets)\b", line):
            label = "unbounded memory copy"
            severity = "HIGH"
        elif re.search(r"(?is)\b(?:memcpy|memmove|strncpy|strncat)\b", line):
            label = "bounded memory copy"
            severity = "MEDIUM"
        elif re.search(r"(?is)\b(?:sprintf|printf|fprintf|snprintf)\b", line):
            label = "memory format function"
            severity = "MEDIUM"
        elif re.search(r"(?:^|[^\w])(?:->|\*)\s*[A-Za-z_$]", line):
            label = "memory cast / arithmetic"
            severity = "MEDIUM"
        elif self.ALLOCATION_RE.search(line):
            if re.search(r"(?is)\(\s*\d+\s*\)", line) or self.numeric_alloc_sizes:
                label = "fixed bounded allocation"
                severity = "MEDIUM"
            else:
                label = "variable-size allocation"
                severity = "MEDIUM"
        else:
            return
        if severity == "MEDIUM" and not self.options.include_low and not (has_taint or self.UNWIND_RE.search(window_text)):
            # Keep informational arbitrary allocation/cast noise down unless context warrants.
            if label in {"memory cast / arithmetic", "fixed bounded allocation", "variable-size allocation"}:
                return
        score = embedded_ai_score(
            sanitize_score_context(window_text),
            heuristic_label=label,
            has_taint=has_taint,
            sanitizer_near=sanitizer_near,
        )
        if score < 0.50 and label not in {"unbounded memory copy", "bounded memory copy", "memory format function"}:
            return
        surface, anomaly, poc, remediation, note = format_detail(label, "Sensitive memory handling pattern")
        if label == "memory format function" and re.search(r"(?is)(?:printf|fprintf|sprintf|snprintf)\s*\(\s*[A-Za-z_$][A-Za-z0-9_$]*\s*[,)]", line):
            score = max(score, embedded_ai_score(window_text, heuristic_label="memory format function", has_taint=has_taint, sanitizer_near=sanitizer_near, extra_positive=1.0))
        self._report(label, severity, line_number, line, surface, anomaly, poc, remediation, "low-to-medium (contextual syntax only)", score)

    def _sink_label(self, line: str) -> Optional[Tuple[str, str]]:
        if self.EXEC_SINKS.search(line):
            return "shell or process invocation", "HIGH"
        if self.SQL_SINKS.search(line):
            return "SQL/database query construction", "HIGH"
        if self.FILE_SINKS.search(line):
            return "file open / include / load", "MEDIUM"
        if self.HTML_SINKS.search(line):
            return "HTML/DOM sink", "HIGH"
        return None

    def _check_tainted_flow(self, line: str, line_number: int) -> None:
        sink = self._sink_label(line)
        if not sink:
            return
        label, severity = sink
        has_direct_source = bool(self.SOURCE_RE.search(line))
        tokens = token_names(line)
        tainted_names = {name for name in self.vars_tainted if name in tokens or f"${name}" in line}
        sanitized_names = {name for name in self.vars_sanitized if name in tokens or f"${name}" in line}
        has_taint = has_direct_source or bool(tainted_names)
        if not has_taint:
            # Argument-only fallback: foo($var) where $var was assigned source earlier.
            for var in sorted(tainted_names):
                if re.search(rf"\(\s*\${re.escape(var)}\s*\)", line):
                    has_taint = True
                    break
        if not has_taint:
            return
        window_text = self._window_text(line_number, line, span=2)
        sanitizer_near = text_has_sanitizer(window_text) or bool(sanitized_names)
        score = embedded_ai_score(
            sanitize_score_context(window_text),
            heuristic_label=label,
            has_taint=has_taint,
            sanitizer_near=sanitizer_near,
        )
        surface, anomaly, poc, remediation, note = format_detail(label, "Tainted data reaches a sensitive sink")
        through = f" Tainted variable(s): {', '.join(sorted(tainted_names))}." if tainted_names else ""
        san = " Sanitizer token(s) nearby lowered confidence." if sanitizer_near else ""
        self._report(
            label,
            severity,
            line_number,
            line,
            surface + through,
            anomaly + san,
            poc,
            remediation,
            "medium (AST/lexical taint heuristic)",
            score,
        )

    def _check_static_patterns(self, line: str, line_number: int) -> None:
        """Incremental crypto/credential checks previously done from full files."""
        sanitizer_near = text_has_sanitizer(line)
        if WEAK_CRYPTO_RE.search(line) and not re.search(r"(?is)password_hash|password_verify|random_bytes|random_int", line):
            score = embedded_ai_score(
                line,
                heuristic_label="weak cryptographic primitive",
                has_taint=False,
                sanitizer_near=sanitizer_near,
            )
            if score >= self.options.min_ai_confidence:
                surface, anomaly, poc, remediation, _ = format_detail("weak cryptographic primitive", "Weak or risky crypto pattern")
                self._report(
                    "weak cryptographic primitive",
                    "MEDIUM",
                    line_number,
                    line,
                    surface,
                    anomaly,
                    poc,
                    remediation,
                    "medium (embedded lexical classifier)",
                    score,
                )
        cred = CREDENTIAL_RE.search(line)
        if cred and not re.search(r"(?is)\$\{|-env-|os\.environ|getenv|secret[_-]?store|vault|kms", line):
            score = embedded_ai_score(
                line,
                heuristic_label="hardcoded credential material",
                has_taint=False,
                sanitizer_near=sanitizer_near,
                extra_positive=0.6,
            )
            if score >= self.options.min_ai_confidence:
                surface, anomaly, poc, remediation, _ = format_detail("hardcoded credential material", "Hardcoded credential material")
                self._report(
                    "hardcoded credential material",
                    "HIGH",
                    line_number,
                    line,
                    surface,
                    anomaly,
                    poc,
                    remediation,
                    "medium (pattern with secret-store exclusions)",
                    score,
                )

    def _process_record(self, scan_data: str, line_number: int, *, is_fragment: bool) -> None:
        if self.limit_reached:
            return
        line = scan_data.rstrip("\r\n")
        if not line:
            self.records_scanned += 1
            self.recent_lines.append((line_number, line))
            return
        if is_fragment:
            line = line + " [truncated]"
        code = self._strip_line_comment(line)
        if code.strip():
            self.records_scanned += 1
            self._update_assignment_state(code)
            self._check_uninitialized(code, line_number)
            self._check_memory(code, line_number)
            self._check_tainted_flow(code, line_number)
            self._check_static_patterns(code, line_number)
            self.recent_lines.append((line_number, line))
        else:
            self.recent_lines.append((line_number, line))


# ----------------------------- AST Analysis Layer -----------------------------

class PythonFlowVisitor(ast.NodeVisitor):
    OUTPUT_KIND_LABELS = {
        "python_execution": "shell or Python execution",
        "python_code": "dynamic code execution",
        "python_sql": "SQL/database query construction",
        "python_path": "file open / include / load",
        "python_html": "HTML sink",
        "python_template": "HTML template rendering",
    }

    def __init__(self, target: str, options: ScanOptions, reporter: OutputReporter) -> None:
        self.target = target
        self.options = options
        self.reporter = reporter
        self.tainted: Set[str] = set()
        self.sanitized: Set[str] = set()
        self.findings_seen: Set[str] = set()
        self.findings = 0
        self.limit_reached = False

    @staticmethod
    def full_name(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = PythonFlowVisitor.full_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Subscript):
            return PythonFlowVisitor.full_name(node.value)
        if isinstance(node, ast.Call):
            return PythonFlowVisitor.full_name(node.func)
        if isinstance(node, ast.Await):
            return PythonFlowVisitor.full_name(node.value)
        return None

    @staticmethod
    def _contains_name(node: ast.AST, names: Iterable[str]) -> bool:
        wanted = set(names)
        for child in ast.walk(node):
            name = PythonFlowVisitor.full_name(child)
            if name and (name in wanted or name.split(".")[0] in wanted):
                return True
        return False

    def _names_used(self, node: ast.AST) -> Set[str]:
        names: Set[str] = set()
        for child in ast.walk(node):
            name = self.full_name(child)
            if name:
                names.add(name)
                if "." in name:
                    names.add(name.split(".", 1)[0])
        return names

    def _is_source(self, node: ast.AST) -> bool:
        names = self._names_used(node)
        lowered = {n.lower() for n in names}
        if lowered & PYTHON_INPUT_NAMES:
            return True
        if isinstance(node, ast.Call):
            name = (self.full_name(node.func) or "").lower()
            if name in {"input", "raw_input", "os.getenv", "getenv"} or name.endswith((".read", ".readline", ".recv", ".recvfrom")):
                return True
        if isinstance(node, ast.Subscript):
            name = (self.full_name(node.value) or "").lower()
            return name in PYTHON_INPUT_NAMES or name.startswith(("os.environ", "request", "flask.request"))
        return False

    def _sanitizer_hit(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = (self.full_name(child.func) or "").lower()
                base = name.split(".")[-1]
                if base in SANITIZER_TOKENS or base in {"escape", "quote", "clean", "bleach"}:
                    return True
        return False

    def _expr_taint(self, node: ast.AST) -> Tuple[bool, Optional[str], bool]:
        if self._is_source(node):
            return True, None, self._sanitizer_hit(node)
        names = self._names_used(node)
        tainted = sorted(names & self.tainted)
        if tainted:
            sanitized_used = bool(names & self.sanitized)
            return True, tainted[0], self._sanitizer_hit(node) or sanitized_used
        return False, None, self._sanitizer_hit(node)

    def _score_and_report(
        self,
        node: ast.AST,
        kind: str,
        text: str,
        tainted_var: Optional[str],
        sanitizer_near: bool,
    ) -> None:
        if self.limit_reached:
            return
        label = self.OUTPUT_KIND_LABELS[kind]
        severity = "HIGH" if kind in {"python_execution", "python_code", "python_sql", "python_html"} else "MEDIUM"
        key = f"{label}|{node.lineno}|{normalize_space(text, 120)}|{tainted_var or ''}"
        if key in self.findings_seen:
            return
        if self.findings >= self.options.max_findings_per_target:
            self.limit_reached = True
            return
        score = embedded_ai_score(
            sanitize_score_context(text),
            heuristic_label=label,
            has_taint=True,
            sanitizer_near=sanitizer_near,
        )
        if score < self.options.min_ai_confidence and sanitizer_near:
            return
        surface, anomaly, poc, remediation, note = format_detail(label, "User-controlled data reaches a sensitive Python API")
        through = f" Tainted variable: {tainted_var}." if tainted_var else " Source expression flows directly to sink."
        san = " Sanitizer token(s) nearby lowered confidence." if sanitizer_near else ""
        finding = Finding(
            target=self.target,
            line=node.lineno,
            severity=severity,
            label=label,
            context=normalize_space(text, 150),
            surface=surface + through,
            anomaly=anomaly + san,
            poc=poc,
            remediation=remediation,
            confidence_note="medium (AST dataflow + embedded classifier)",
            ai_score=score,
            source="python-ast",
        )
        self.findings_seen.add(key)
        self.findings += 1
        self.reporter.finding(finding)

    def visit_Assign(self, node: ast.Assign) -> None:
        is_taint, taint_name, san_hit = self._expr_taint(node.value)
        target_names = []
        for target in node.targets:
            name = self.full_name(target)
            if name:
                target_names.append(name)
        if is_taint and not san_hit:
            self.tainted.update(target_names)
        elif san_hit:
            self.sanitized.update(target_names)
            self.tainted.difference_update(target_names)
        else:
            names = self._names_used(node.value)
            for name in target_names:
                if names & self.tainted:
                    self.tainted.add(name)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        name = self.full_name(node.target)
        if node.value is not None:
            is_taint, _, san_hit = self._expr_taint(node.value)
            if name and is_taint and not san_hit:
                self.tainted.add(name)
            elif name and san_hit:
                self.sanitized.add(name)
                self.tainted.discard(name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = (self.full_name(node.func) or "").lower()
        kind: Optional[str] = None
        base_name = name.rsplit(".", 1)[-1]
        if name.endswith(("os.system", "os.popen")) or name.endswith(("subprocess.run", "subprocess.popen", "subprocess.call", "subprocess.check_output")) or base_name in {"system", "popen"}:
            kind = "python_execution"
        elif name in {"eval", "exec", "compile"} or name.endswith((".__import__",)):
            kind = "python_code"
        elif name.endswith(("execute", "executemany", "executescript")) or ".query" in name:
            kind = "python_sql"
        elif name in {"open", "io.open", "codecs.open"} or name.endswith((".load", ".loads", "pickle.loads", "yaml.load", "__import__")):
            kind = "python_path"
        elif name.endswith((".send", ".write")) and any("html" in a.lower() for a in self._names_used(node)):
            kind = "python_html"
        elif name.endswith(("render", "render_template", "templateresponse", "markupsafe.markup")):
            kind = "python_template"
        if kind:
            segments: List[str] = [f"line {node.lineno} call {name}"]
            tainted_first: Optional[str] = None
            sanitizer_near = False
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                try:
                    seg = ast.unparse(arg)
                except Exception:
                    seg = ast.dump(arg)[:200]
                segments.append(seg)
                taint, var, san_hit = self._expr_taint(arg)
                sanitizer_near = sanitizer_near or san_hit
                if taint and tainted_first is None:
                    tainted_first = var or "direct source expression"
            if tainted_first is not None:
                joined = " | ".join(segments)
                self._score_and_report(node, kind, joined, tainted_first, sanitizer_near)
        self.generic_visit(node)


def scan_python_ast(target: str, source: str, options: ScanOptions, reporter: OutputReporter) -> Tuple[int, int]:
    try:
        tree = ast.parse(source, filename=target, mode="exec")
    except (SyntaxError, ValueError, MemoryError) as exc:
        reporter.warn(f"Python AST fallback for {target}: {exc}")
        return 0, 0
    visitor = PythonFlowVisitor(target, options, reporter)
    visitor.visit(tree)
    return len(source.splitlines()), visitor.findings


# ----------------------------- Whole-file pattern helpers -----------------------------

WEAK_CRYPTO_RE = re.compile(r"(?is)\b(?:md5|sha1|des|ecb|mcrypt|static\s+(?:key|iv)|hardcoded[_-]?(?:key|secret|password))\b")
CREDENTIAL_RE = re.compile(
    r"(?is)\b(?:api[_-]?key|secret(?:_key)?|pass(?:word|wd)|passwd|private[_-]?key|token)\b\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
)
FIXED_SAFE_LINE = re.compile(r"(?is)^\s*(?:echo|print|printf|document\.write)?\s*[('\"][^('\"]{0,200}[)'\"]\s*[;)]?\s*$")


def whole_file_checks(target: str, source: str, options: ScanOptions, reporter: OutputReporter) -> int:
    findings = 0
    seen_lines: Set[int] = set()
    lines = source.splitlines()
    for idx, line in enumerate(lines, 1):
        if idx in seen_lines:
            continue
        sanitizer_near = text_has_sanitizer(line)
        if WEAK_CRYPTO_RE.search(line) and not re.search(r"(?is)password_hash|password_verify|random_bytes|random_int", line):
            score = embedded_ai_score(line, heuristic_label="weak cryptographic primitive", has_taint=False, sanitizer_near=sanitizer_near)
            if score >= options.min_ai_confidence:
                surface, anomaly, poc, remediation, note = format_detail("weak cryptographic primitive", "Weak or risky crypto pattern")
                finding = Finding(
                    target=target,
                    line=idx,
                    severity="MEDIUM",
                    label="weak cryptographic primitive",
                    context=normalize_space(line),
                    surface=surface,
                    anomaly=anomaly,
                    poc=poc,
                    remediation=remediation,
                    confidence_note="medium (embedded lexical classifier)",
                    ai_score=score,
                    source="whole-file",
                )
                reporter.finding(finding)
                findings += 1
                seen_lines.add(idx)
        cred = CREDENTIAL_RE.search(line)
        if cred and not re.search(r"(?is)\$\{|-env-|os\.environ|getenv|secret[_-]?store|vault|kms", line):
            score = embedded_ai_score(line, heuristic_label="hardcoded credential material", has_taint=False, sanitizer_near=sanitizer_near, extra_positive=0.6)
            if score >= options.min_ai_confidence:
                surface, anomaly, poc, remediation, note = format_detail("hardcoded credential material", "Hardcoded credential material")
                finding = Finding(
                    target=target,
                    line=idx,
                    severity="HIGH",
                    label="hardcoded credential material",
                    context=normalize_space(line),
                    surface=surface,
                    anomaly=anomaly,
                    poc=poc,
                    remediation=remediation,
                    confidence_note="medium (pattern with secret-store exclusions)",
                    ai_score=score,
                    source="whole-file",
                )
                reporter.finding(finding)
                findings += 1
                seen_lines.add(idx)
        if findings >= options.max_findings_per_target:
            break
    return findings


# ----------------------------- File scanning and progress -----------------------------

def decode_bytes(data: bytes) -> Tuple[str, str]:
    if not data:
        return "", "empty"
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace"), "utf-8-replace"


def scan_stream_target(
    uri: str,
    stream: BinaryIO,
    kind: str,
    options: ScanOptions,
    reporter: OutputReporter,
    expected_size: Optional[int] = None,
    runtime_size_limit: Optional[int] = None,
) -> Tuple[int, int, int]:
    """Scan any already-open binary stream in bounded requested blocks.

    This function is shared by regular files and archive member streams. It
    reads at most ``options.read_chunk_size`` (hard-limited by
    ``DEFAULT_READ_CHUNK_SIZE``) per cycle, feeds the lexical/flow scanner,
    then explicitly releases each block. Python sources are additionally
    captured only up to MAX_AST_SOURCE_BYTES for the AST pass; that bounded
    capture does not materialize archive members as files.
    """
    if expected_size == 0:
        raise ScanError(f"target stream is empty: {uri}")
    scanner = LogicalScanner(uri, options, reporter)
    processed = 0
    block = 0
    ast_capture = bytearray() if kind == "python" else None
    ast_capture_truncated = False
    try:
        while True:
            read_request = options.read_chunk_size
            if runtime_size_limit is not None:
                remaining = runtime_size_limit - processed
                if remaining < 0:
                    raise ScanError(f"target stream exceeded {runtime_size_limit} bytes: {uri}")
                # Read one byte beyond the allowance only to distinguish an
                # over-limit member from an exact-boundary EOF.
                read_request = min(read_request, remaining + 1)
            try:
                chunk_data = stream.read(read_request)
            except (OSError, MemoryError, RuntimeError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
                raise ScanError(f"read failed for {uri}: {exc}") from exc
            if not chunk_data:
                break
            if runtime_size_limit is not None and processed + len(chunk_data) > runtime_size_limit:
                del chunk_data
                raise ScanError(f"target stream exceeded {runtime_size_limit} bytes: {uri}")
            if ast_capture is not None:
                remaining = MAX_AST_SOURCE_BYTES - len(ast_capture)
                if remaining > 0:
                    ast_capture.extend(chunk_data[:remaining])
                if processed + len(chunk_data) > MAX_AST_SOURCE_BYTES:
                    ast_capture_truncated = True
            scanner.feed(chunk_data)
            processed += len(chunk_data)
            block += 1
            if expected_size:
                percent = min(100.0, (processed / expected_size) * 100)
                size_part = f"{processed}/{expected_size} bytes ({percent:0.1f}%)"
            else:
                size_part = f"{processed} bytes"
            reporter.progress(
                f"{uri}: {size_part} | block={block} | "
                f"completed-lines={scanner.line_number} | scanned-records={scanner.records_scanned}"
            )
            # Strict per-cycle release requested for all providers, including
            # decompressed ZIP/TAR member streams.
            del chunk_data
            if block % 4 == 0:
                gc.collect()
    finally:
        if scanner.limit_reached:
            reporter.warn(f"{uri}: stopped early after configured finding limit.")
    if processed == 0:
        raise ScanError(f"target stream is empty: {uri}")
    scanner._finish_physical_line(force_empty=True)

    if kind == "python":
        if ast_capture_truncated:
            reporter.warn(f"{uri}: skipped Python AST layer; source exceeds {MAX_AST_SOURCE_BYTES} bytes.")
        elif ast_capture is not None and len(ast_capture):
            source, _ = decode_bytes(bytes(ast_capture))
            try:
                _ast_lines, ast_findings = scan_python_ast(uri, source, options, reporter)
                scanner.findings += ast_findings
            finally:
                del source
        del ast_capture
    return scanner.line_number, scanner.findings, processed


def scan_bytes_stream(target: str, data: bytes, kind: str, options: ScanOptions, reporter: OutputReporter) -> Tuple[int, int, int, str]:
    if not data:
        raise ScanError(f"target stream is empty: {target}")
    stream = io.BytesIO(data)
    try:
        lines, findings, total = scan_stream_target(target, stream, kind, options, reporter, len(data))
        return lines, findings, total, "stream"
    finally:
        stream.close()
        del stream
        gc.collect()


def scan_regular_file(path: str, kind: str, options: ScanOptions, reporter: OutputReporter) -> Tuple[int, int, int]:
    reader = TargetReader(options, reporter)
    identity = reader._identity_for_path(path)
    size = identity[2]
    if size == 0:
        raise ScanError(f"target file is empty: {path}")
    stream, close_stream = TargetReader._regular_file_opener(path, identity)()
    try:
        return scan_stream_target(path, stream, kind, options, reporter, size)
    finally:
        close_stream()
        del stream
        del reader
        gc.collect()


# ----------------------------- Target routing & CLI -----------------------------

def scan_stream_job(job: ScanJob, options: ScanOptions, reporter: OutputReporter) -> Tuple[int, int, int]:
    stream, close_stream = job.stream_opener()
    try:
        runtime_limit = options.max_member_bytes if job.bounded_member else None
        return scan_stream_target(
            job.uri,
            stream,
            job.kind,
            options,
            reporter,
            job.expected_size,
            runtime_limit,
        )
    finally:
        try:
            close_stream()
        finally:
            del stream
            gc.collect()


def collect_targets(args: argparse.Namespace, options: ScanOptions, reporter: OutputReporter) -> Iterator[ScanJob]:
    reader = TargetReader(options, reporter)
    produced = 0
    for target in args.targets or []:
        try:
            for job in reader.list_local_jobs(target):
                produced += 1
                yield job
                if produced % 8 == 0:
                    gc.collect()
        except ScanError as exc:
            reporter.error(str(exc))
    if args.s3_bucket or args.s3_key:
        if not (args.s3_bucket and args.s3_key):
            reporter.error("--s3-bucket and --s3-key must be supplied together.")
        else:
            try:
                blob = fetch_s3_to_memory(options, reporter, args.s3_bucket, args.s3_key, args.s3_region)
                virtual = f"s3://{args.s3_bucket}/{args.s3_key}"
                try:
                    for job in reader.iter_blob_jobs(virtual, blob, 0):
                        produced += 1
                        yield job
                        if produced % 8 == 0:
                            gc.collect()
                finally:
                    # Job openers that need the S3/nested archive retain their
                    # own bounded parent bytes; this removes only the router ref.
                    del blob
                    gc.collect()
            except ScanError as exc:
                reporter.error(str(exc))


def positive_int(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected integer, got {value!r}") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    epilog = """
Privacy / policy notes:
  * Default local scanning is offline for analysis and writes only stdout/stderr.
  * ZIP and TAR/TAR.GZ leaf members are stream-decompressed and scanned in
    memory; the tool never writes extracted member files to a temporary path.
  * --s3-bucket/--s3-key opens a read-only stream to the endpoint selected by
    AWS_ENDPOINT_URL_S3 (default http://127.0.0.1:4566). AWS receives request
    metadata and credentials if present; use --no-s3 to force local-only runs.
  * No AI APIs, model downloads, telemetry, or uploads are used. The AI score is
    an embedded deterministic classifier.

Targets:
  paths             one or more local files or directories (directories recurse)
  --s3-bucket B     S3 bucket for one read-only object scan
  --s3-key K        S3 object key to scan

Examples:
  python3 disk_stream_scanner.py src/main.py
  python3 disk_stream_scanner.py ./workspace --include-low
  python3 disk_stream_scanner.py package.tar.gz --max-concurrent-files 2
  AWS_ENDPOINT_URL_S3=http://127.0.0.1:4566 python3 disk_stream_scanner.py \
      --s3-bucket my-bucket --s3-key source.zip
"""
    parser = argparse.ArgumentParser(
        prog="disk_stream_scanner.py",
        description=(
            "Private, standard-library-only static triage scanner with bounded 100 MiB block reads, "
            "streaming in-memory ZIP/TAR.GZ member routing, a Python AST dataflow layer, lexical fallback tracking, "
            "and an embedded TF-IDF/logistic confidence score."
        ),
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("targets", nargs="*", help="local files or directories to scan")
    parser.add_argument("--target", dest="target_flag", action="append", default=[], help="additional local file or directory target")
    parser.add_argument("--s3-bucket", help="read one S3 object from this bucket (requires --s3-key)")
    parser.add_argument("--s3-key", help="S3 object key to stream and scan (requires --s3-bucket)")
    parser.add_argument("--s3-region", help="AWS region for optional SigV4 signing (defaults to AWS_REGION/AWS_DEFAULT_REGION/us-east-1)")
    parser.add_argument("--no-s3", action="store_true", help="strict offline mode: reject S3 flags and require local targets only")
    parser.add_argument("--chunk-size", type=positive_int, default=DEFAULT_READ_CHUNK_SIZE,
                        help=f"requested bytes per read cycle (default and maximum: {DEFAULT_READ_CHUNK_SIZE})")
    parser.add_argument("--max-member-bytes", type=positive_int, default=DEFAULT_MAX_MEMBER_BYTES,
                        help=f"best-effort cap for each streamed archive/S3 object or nested archive (default: {DEFAULT_MAX_MEMBER_BYTES})")
    parser.add_argument("--max-concurrent-files", type=positive_int, default=DEFAULT_MAX_CONCURRENT_FILES,
                        help=f"number of local files scanned concurrently (default: {DEFAULT_MAX_CONCURRENT_FILES})")
    parser.add_argument("--min-ai-confidence", type=float, default=DEFAULT_MIN_AI_CONFIDENCE,
                        help=f"minimum embedded classifier score for whole-file/classifier-gated leads (default: {DEFAULT_MIN_AI_CONFIDENCE})")
    parser.add_argument("--include-low", action="store_true", help="include lower-confidence allocation/cast style leads")
    parser.add_argument("--max-findings-per-target", type=positive_int, default=250,
                        help="stop scanning chunks for a target after this many findings (default: 250)")
    parser.add_argument("--color", action="store_true", help="force ANSI color output")
    parser.add_argument("--verbose", action="store_true", help="include verbose processing diagnostics")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def parse_extensions(args: argparse.Namespace) -> Set[str]:
    return set(DEFAULT_SOURCE_EXTENSIONS)


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> bool:
    if args.chunk_size > DEFAULT_READ_CHUNK_SIZE:
        parser.error(f"--chunk-size cannot exceed {DEFAULT_READ_CHUNK_SIZE} bytes")
    if args.chunk_size <= 0:
        parser.error("--chunk-size must be positive")
    if args.no_s3 and (args.s3_bucket or args.s3_key):
        parser.error("--s3-bucket/--s3-key are incompatible with --no-s3")
    if (args.s3_bucket and not args.s3_key) or (args.s3_key and not args.s3_bucket):
        parser.error("--s3-bucket and --s3-key must be supplied together")
    if not args.targets and not args.target_flag and not args.s3_bucket:
        parser.error("provide at least one target path, --target, or --s3-bucket/--s3-key")
    return True


def scan_collect_output(job: ScanJob, options: ScanOptions, reporter: OutputReporter) -> Tuple[str, int, int, int, Optional[str]]:
    file_content: Optional[BinaryIO] = None
    close_stream: Optional[Callable[[], None]] = None
    auditor: Optional[str] = None
    try:
        # The opener may produce a ZIP/TAR member stream directly; no temporary
        # extraction path or whole-member payload is created for leaf members.
        auditor = f"logical-auditor:{job.uri}"
        file_content, close_stream = job.stream_opener()
        lines, findings, bytes_read = scan_stream_target(
            job.uri,
            file_content,
            job.kind,
            options,
            reporter,
            job.expected_size,
        )
        reporter.target_done(job.uri, bytes_read, lines, findings)
        return job.uri, lines, findings, bytes_read, None
    except ScanError as exc:
        reporter.error(str(exc))
        return job.uri, 0, 0, 0, str(exc)
    except (OSError, RuntimeError, ValueError, tarfile.TarError, zipfile.BadZipFile, MemoryError) as exc:
        message = f"target unreadable {job.uri}: {exc}"
        reporter.error(message)
        return job.uri, 0, 0, 0, message
    finally:
        if close_stream is not None:
            try:
                close_stream()
            except Exception as exc:  # close must not discard study results
                reporter.warn(f"cleanup failed for {job.uri}: {exc}")
        # Explicit threshold deallocation requested for every scanned-file loop.
        del file_content
        del auditor
        gc.collect()


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.targets = (args.targets or []) + list(args.target_flag or [])
    validate_args(parser, args)
    options = ScanOptions(
        extensions=parse_extensions(args),
        read_chunk_size=min(args.chunk_size, DEFAULT_READ_CHUNK_SIZE),
        max_member_bytes=args.max_member_bytes,
        max_concurrent_files=max(1, min(args.max_concurrent_files, 16)),
        min_ai_confidence=max(0.0, min(args.min_ai_confidence, 0.99)),
        include_low=args.include_low,
        pretty_color=args.color or supports_ansi(),
        max_findings_per_target=args.max_findings_per_target,
        verbose=args.verbose,
        no_s3=args.no_s3,
    )
    reporter = OutputReporter(options.pretty_color)
    reporter.info(
        f"disk_stream_scanner {VERSION} | local/private analysis | requested block={options.read_chunk_size} bytes | "
        f"archive member cap={options.max_member_bytes} bytes | threads={options.max_concurrent_files}"
    )
    reporter.info("archive mode: ZIP/TAR members are opened as in-memory streams; no extraction files are written.")
    failed = False
    scanned = 0
    aggregate_findings = 0
    jobs: List[ScanJob] = list(collect_targets(args, options, reporter))
    if not jobs:
        reporter.error("no scannable source/archive members were produced from the requested target(s).")
        return 2
    try:
        if options.max_concurrent_files == 1:
            for job in jobs:
                _, _lines, findings, _bytes_read, error = scan_collect_output(job, options, reporter)
                scanned += 1 if not error else 0
                aggregate_findings += findings
                if error:
                    failed = True
        else:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=options.max_concurrent_files,
                thread_name_prefix="scanner",
            ) as pool:
                future_map = {
                    pool.submit(scan_collect_output, job, options, reporter): job.uri
                    for job in jobs
                }
                for future in concurrent.futures.as_completed(future_map):
                    uri = future_map[future]
                    try:
                        _, _lines, findings, _bytes_read, error = future.result()
                    except Exception as exc:  # defensive worker boundary
                        reporter.error(f"worker failed for {uri}: {exc}")
                        failed = True
                        continue
                    scanned += 1 if not error else 0
                    aggregate_findings += findings
                    if error:
                        failed = True
    finally:
        # Remove stream factory refs; archive closures may reference bounded
        # parent payload bytes for S3 or nested archive cases.
        jobs.clear()
        del jobs
        gc.collect()
    reporter.info(f"scan complete: {scanned} object(s), {aggregate_findings} finding(s).")
    reporter.warn(
        "Heuristic static analysis only: it cannot prove exploitability, guarantee zero-day discovery, "
        "or prove a target is safe. Review all leads in authorized testing."
    )
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        raise SystemExit(1)
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted by user.\n")
        raise SystemExit(130)
