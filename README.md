# bcrypt 5-Digit PIN Cracker (educational demo)

Brute-force a **bcrypt** hash to recover a **5-digit numeric PIN** (`00000`–`99999`).

> ⚠️ **Honest framing:** bcrypt is a *one-way* hash. There is **no decryption**.
> The only way to recover a password is to guess candidates and verify each one.
> This tool searches the only keyspace where that is practical for a short numeric
> secret: **100,000 candidates**. Use it only on hashes you are authorized to test.

## What's in here

| File | Purpose |
|------|---------|
| `cracker.py` | Python brute-forcer (single-process + multiprocessing) with a CLI. |
| `index.html` | Static site: a **live, working in-browser cracker** + docs. |
| `assets/js/worker.js` | Web Worker running real bcrypt checks in the browser. |
| `assets/js/app.js` | UI, starfield, demo-hash generation. |
| `assets/css/style.css` | Dark animated theme. |
| `vendor/bcrypt.min.js` | Vendored bcrypt.js (dcodeIO) so the page works offline / on Pages. |
| `requirements.txt` | `bcrypt` for the Python script. |

## Why only 5 digits?

Because bcrypt is intentionally **slow per check**, the wall-clock time depends on
the hash's *cost factor* (the `04` / `10` / `12` in `$2b$12$…`):

| Cost | Per check | 100k candidates |
|------|-----------|-----------------|
| 4    | ~1 ms     | seconds         |
| 6    | ~5 ms     | ~10 min         |
| 10   | ~70 ms    | ~2 h            |
| 12   | ~320 ms   | ~9 h            |

100,000 guesses is trivial *only* at low cost. For a real (unconstrained) password
this is completely infeasible — that's the point of bcrypt.

## Python usage

```bash
pip install -r requirements.txt

# crack a hash (single process)
python cracker.py '$2b$04$...'

# use all your CPU cores
python cracker.py '$2b$04$...' --workers 4

# or pipe the hash in
echo '$2b$04$...' | python cracker.py
```

Exit codes: `0` = found, `1` = not found, `2` = bad input/invalid hash.

## Web demo

Open `index.html` (or the deployed GitHub Pages site). Click **Use demo hash**
then **Start crack** — it generates a real cost-4 hash of `00042` in your browser,
then a Web Worker brute-forces it back. No server, no data leaves your machine.

## Ethics & legality

Cracking hashes you do not have permission to attack is illegal. This repository is
for: your own accounts/passwords, CTF challenges you're permitted to solve, and
learning how password hashing actually defends against brute force.
