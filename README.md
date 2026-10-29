# Disk Stream Scanner

Disk Stream Scanner is a private, lightweight, heuristic static-triage scanner built entirely on the Python standard library. It is designed to run completely offline without relying on AI APIs, cloud infrastructure, or external model dependencies, ensuring that your source code, taint paths, and findings never leave your local environment.

## Core Features

- **In-Memory Streaming Engine:** Leaf members inside ZIP, TAR, and TAR.GZ archives are decompressed and consumed in bounded read blocks; they are never materialized as temporary files on disk.
- **Hybrid Analysis Architecture:** Features a robust Python AST dataflow tracking engine alongside a sliding-window lexical scanner for languages like C, PHP, Go, and JavaScript.
- **Embedded Confidence Layer:** Employs a deterministic, offline TF-IDF/logistic scoring algorithm to prioritize high-fidelity findings without external AI connections.
- **S3 Read-Only Pipeline:** Optional support for opening secure, direct streams from AWS S3 (compatible with local test setups like LocalStack) while respecting memory caps.

## Quick Start

### Installation
No installation or external package dependencies required. Simply download `disk_stream_scanner.py` and run it using Python 3.8+.

```bash
chmod +x disk_stream_scanner.py
```

### Examples

Scan a single local source file:
```bash
python3 disk_stream_scanner.py src/main.py
```

Scan a directory recursively and include lower-confidence memory layer leads:
```bash
python3 disk_stream_scanner.py ./workspace --include-low
```

Stream and scan a compressed archive while limiting threading context:
```bash
python3 disk_stream_scanner.py package.tar.gz --max-concurrent-files 2
```

Stream directly from a LocalStack S3 bucket:
```bash
AWS_ENDPOINT_URL_S3=http://127.0.0.1:4566 python3 disk_stream_scanner.py --s3-bucket my-bucket --s3-key source.zip
```

## CLI Configuration Options

| Option | Default | Description |
|---|---|---|
| `--chunk-size` | `104857600` | Requested bytes per read block cycle (Max 100 MiB). |
| `--max-member-bytes`| `134217728` | Best-effort cap for each streamed archive file (128 MiB). |
| `--max-concurrent-files`| `4` | Number of files scanned concurrently. |
| `--min-ai-confidence` | `0.55` | Confidence filter floor for whole-file triggers. |
| `--include-low` | `False` | Includes low-level memory assignment/cast analysis. |
| `--no-s3` | `False` | Enforces absolute offline mode; explicitly blocks network flags. |

## Scope and Safety Limits

Static analysis tools are pre-review optimization filters and cannot guarantee zero-day discovery or prove absolute software safety. Always validate code leads and potential logic gaps within authorized, isolated sandbox environments.
