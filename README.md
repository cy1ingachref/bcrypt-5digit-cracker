# bcrypt 5-Digit PIN Cracker

[![CI](https://github.com/cy1ingachref/bcrypt-5digit-cracker/actions/workflows/ci.yml/badge.svg)](https://github.com/cy1ingachref/bcrypt-5digit-cracker/actions/workflows/ci.yml)

A focused, educational tool to brute-force 5-digit numeric PINs (00000–99999) from bcrypt hashes. Intended for security auditing, research, and learning — not for unauthorized access.

> ⚠️ **Important**: bcrypt is a one-way hash. There is no decryption — this tool verifies candidate PINs against a hash. Use only on hashes you own or have explicit permission to test.

## Project overview

This repository contains:

- `cracker.py` — A Python brute-force script with single-process and multiprocessing support
- `index.html` and `assets/` — A browser-based demo that runs bcrypt checks in a Web Worker
- `vendor/bcrypt.min.js` — Vendored bcrypt.js for offline Pages/demo usage
- `requirements.txt` — Python dependencies

## Quick start

```bash
pip install -r requirements.txt
python cracker.py --hash '$2b$12$...' --min 0 --max 99999
```

Or use the browser demo by opening `index.html` in any modern browser.

## Why this exists

bcrypt is designed to be slow per-check, so brute-forcing is only feasible with a tiny keyspace (100k candidates for 5-digit PINs). This demonstrates why PINs make poor passwords and why cost factors matter.

## Tests

```bash
pytest tests/
```

Uses low-cost hashes (cost 4) for fast, deterministic tests.

## License

MIT
