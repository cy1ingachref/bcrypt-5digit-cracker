# bcrypt 5-Digit PIN Cracker

A focused, high-performance educational tool to brute-force 5-digit numeric PINs (00000–99999) from bcrypt hashes. Intended for security auditing, research, and learning — not for unauthorized access.

> ⚠️ Important: bcrypt is a one‑way hash. There is no decryption — this tool verifies candidate PINs against a hash. Use only on hashes you own or have explicit permission to test.

## Project overview

This repository contains:

- `cracker.py` — A Python brute-force script (single-process and multiprocessing support) with a simple CLI.
- `index.html` and `assets/` — A browser-based demo that runs bcrypt checks in a Web Worker.
- `vendor/bcrypt.min.js` — Vendored bcrypt.js for offline Pages/demo usage.
- `requirements.txt` — Python dependencies (e.g., `bcrypt`).

The project demonstrates the security properties and limitations of short numeric passwords even when protected with bcrypt. It intentionally targets a constrained keyspace (100,000 candidates) to keep runtime practical for demonstrations.

## Why 5 digits?

bcrypt is intentionally slow by design. The practical time to exhaustively check candidates depends on the cost factor (the `$2b$12$` portion of the hash). A 5-digit numeric PIN limits the keyspace to 100,000 candidates, which makes exhaustive verification feasible for demonstrations at low cost factors.

Cost factor examples (approximate per-check times):

| Cost | Per check | 100k candidates |
|------|-----------:|----------------:|
| 4    | ~1 ms      | seconds         |
| 6    | ~5 ms      | minutes         |
| 10   | ~70 ms     | hours           |
| 12   | ~320 ms    | many hours      |

For real, unconstrained passwords, brute forcing bcrypt is impractical — that's the protection bcrypt provides.

## Quickstart — Python

1. Create and activate a virtual environment (recommended):

```bash
python3 -m venv venv
source venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Examples

Single-process:

```bash
python cracker.py '$2b$04$...'
```

Using multiple workers (use the number of CPU cores appropriate for your system):

```bash
python cracker.py '$2b$04$...' --workers 4
```

Pipe the hash via stdin:

```bash
echo '$2b$04$...' | python cracker.py
```

Exit codes:
- `0` = PIN found
- `1` = PIN not found
- `2` = invalid input / bad hash

Note: Runtime depends on bcrypt cost factor and available CPU. Use responsibly.

## Web demo

Open `index.html` locally or visit the GitHub Pages deployment (if available). The demo:

- Generates a demo bcrypt hash in the browser (cost=4 by default) for a known 5-digit PIN.
- Uses a Web Worker (`assets/js/worker.js`) to brute-force the PIN entirely in the browser — no server, no data leaves your machine.

This demo is intended for educational purposes only.

## Responsible use and legal notice

This tool is intended for password-auditing, research, and education. Unauthorized use against accounts, systems, or data you do not own is illegal and unethical. The repository owner and contributors are not responsible for misuse. Always obtain explicit authorization before testing.

## Contributing

Contributions that improve documentation, clarify ethical guidance, or enhance the demo are welcome. Please open issues or pull requests and follow standard contribution practices. If you plan to contribute code that increases cracking performance, include clear safety guidance and consider opt-in feature flags so the demo remains suitable for educational use.