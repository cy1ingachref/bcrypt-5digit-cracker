#!/usr/bin/env python3
"""
bcrypt 5-digit numeric password cracker.

IMPORTANT / HONEST NOTE
-----------------------
bcrypt is a *one-way* cryptographic hash. There is no "decryption" of a bcrypt
hash. The only way to recover a password is to GUESS candidate passwords and
check each one against the stored hash until a match is found. This is a
brute-force search over the keyspace of all 5-digit numeric PINs:

        00000, 00001, ..., 99999   ->   exactly 100,000 candidates

This is feasible ONLY because the keyspace is tiny (100k). bcrypt is designed to
be slow per-check, so the wall-clock time depends entirely on the hash's *cost
factor* (the `log_rounds` encoded in the hash, e.g. the "12" in
`$2b$12$...`). Roughly:

    cost  4  ->  ~seconds        (demo / legacy)
    cost  6  ->  ~10 minutes
    cost 10  ->  ~2 hours
    cost 12  ->  ~9 hours        (modern default)

Use this tool only against hashes you are authorized to test (your own
accounts, CTF challenges you are allowed to solve, passwords you forgot for
your own data). Cracking hashes you do not have permission to attack is illegal.

Usage (CLI):
    python cracker.py '$2b$04$...hashed...'            # single process
    python cracker.py '$2b$04$...hashed...' --workers 4 # multiprocessing
    echo '$2b$04$...hashed...' | python cracker.py      # read hash from stdin

Programmatic:
    from cracker import crack
    result = crack(hash_str, workers=4)
    # -> ('12345', 3.21)  on success  or  (None, 12.0)  if not found
"""

from __future__ import annotations

import sys
import time
import re
import argparse
from typing import Optional, Tuple

import bcrypt


# ---------------------------------------------------------------------------
# Core brute-force routine
# ---------------------------------------------------------------------------
def _batch_check(arg: tuple) -> Optional[str]:
    """Worker entry: arg = (hash_bytes, start, end). Returns match or None.

    Defined as a single-argument function on purpose: multiprocessing's
    imap_unordered auto-spreads one iterable per call, so we bundle the
    params into one tuple (also keeps it picklable for spawn on Windows).
    """
    hash_bytes, start, end = arg
    for i in range(start, end):
        cand = f"{i:05d}".encode("ascii")
        if bcrypt.checkpw(cand, hash_bytes):
            return f"{i:05d}"
    return None


def cost_of(hash_str: str) -> Optional[int]:
    """Return the bcrypt cost factor (log2 rounds) encoded in the hash, or None."""
    m = re.match(r"^\$2[aby]\$(\d{1,2})\$", hash_str)
    return int(m.group(1)) if m else None


# Rough seconds-per-100k-candidates at each cost factor, measured on a
# typical laptop CPU. Used only for an up-front ETA warning.
_COST_ETA = {4: 3, 5: 6, 6: 12, 7: 25, 8: 50, 9: 100, 10: 200, 11: 400, 12: 800}


def _warn_cost(hash_str: str, verbose: bool) -> None:
    if not verbose:
        return
    c = cost_of(hash_str)
    if c is None:
        sys.stderr.write("  [warn] could not parse cost factor from hash\n")
        return
    eta = _COST_ETA.get(c, _COST_ETA[12] * (2 ** (c - 12)))
    if c >= 10:
        sys.stderr.write(
            f"  [warn] cost {c}: full 100k search ~{eta/60:.0f} min on one core "
            f"(~{eta/3600:.1f} h). Use a lower-cost hash for quick demos.\n"
        )
    else:
        sys.stderr.write(f"  [info] cost {c}: full 100k search ~{eta}s on one core\n")


def crack(hash_str: str,
          workers: int = 1,
          verbose: bool = True,
          max_pin: int = 99_999) -> Tuple[Optional[str], float]:
    """Brute-force a bcrypt hash against every 5-digit numeric PIN (00000-max_pin).

    Args:
        hash_str: the bcrypt hash, e.g. "$2b$04$..."
        workers:  number of worker processes (>=1).
        verbose:  print progress / timing / ETA to stderr.
        max_pin:  upper bound of the keyspace (inclusive). Default 99999.

    Returns:
        (password, elapsed_seconds) on success, or (None, elapsed_seconds).
    """
    if not (0 <= max_pin <= 99_999):
        raise ValueError("max_pin must be between 0 and 99_999")
    hash_bytes = hash_str.encode("ascii")
    # Validate it is actually a bcrypt hash we can check.
    try:
        bcrypt.checkpw(b"00000", hash_bytes)  # will return False unless it matches
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Not a valid bcrypt hash: {exc}") from exc

    _warn_cost(hash_str, verbose)

    total = max_pin + 1
    start_time = time.time()
    found: Optional[str] = None

    if workers <= 1:
        # Simple single-process path (no multiprocessing overhead).
        for i in range(total):
            if bcrypt.checkpw(f"{i:05d}".encode("ascii"), hash_bytes):
                found = f"{i:05d}"
                break
            if verbose and (i + 1) % 20_000 == 0:
                done = i + 1
                elapsed = time.time() - start_time
                rate = done / elapsed if elapsed else 0
                remain = (total - done) / rate if rate else 0
                sys.stderr.write(
                    f"  checked {done:,}/{total:,} "
                    f"({done/total*100:.0f}%)  elapsed {elapsed:.1f}s  "
                    f"ETA ~{remain/60:.1f} min\n"
                )
    else:
        # NOTE: on Windows the default start method is 'spawn', which requires
        # the mapped function to be picklable (a module-level function, NOT a
        # lambda / closure). Use a top-level function + plain tuples.
        import multiprocessing as mp
        try:
            ctx = mp.get_context("spawn")
            chunk = total // workers
            ranges = [(r * chunk, (r + 1) * chunk if r < workers - 1 else total)
                      for r in range(workers)]
            args = [(hash_bytes, s, e) for (s, e) in ranges]
            with ctx.Pool(processes=workers) as pool:
                try:
                    for res in pool.imap_unordered(_batch_check, args):
                        if res is not None:
                            found = res
                            break
                except KeyboardInterrupt:
                    pool.terminate()
                    pool.join()
                    raise
                finally:
                    # Stop any remaining workers promptly (also handles early break).
                    pool.terminate()
                    pool.join()
        except (OSError, RuntimeError) as exc:
            # Windows spawn can intermittently fail with Win32 handle errors
            # (PermissionError / WinError 5). Fall back to single-process so
            # the tool still completes the job instead of crashing.
            if verbose:
                sys.stderr.write(
                    f"  [warn] multiprocessing unavailable ({exc}); "
                    f"falling back to single process\n"
                )
            for i in range(total):
                if bcrypt.checkpw(f"{i:05d}".encode("ascii"), hash_bytes):
                    found = f"{i:05d}"
                    break

    elapsed = time.time() - start_time
    if verbose:
        if found:
            sys.stderr.write(
                f"[+] FOUND password '{found}' in {elapsed:.2f}s "
                f"using {workers} worker(s)\n"
            )
        else:
            sys.stderr.write(
                f"[-] Not found after checking all 100,000 candidates "
                f"({elapsed:.2f}s)\n"
            )
    return found, elapsed


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _read_hash_arg(args_hash: Optional[str]) -> str:
    if args_hash:
        return args_hash.strip()
    data = sys.stdin.read().strip()
    if not data:
        raise SystemExit("error: no hash provided (arg or stdin)")
    # take the first token in case of pasted multi-line text
    return data.split()[0]


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(
        description="Brute-force a bcrypt hash against all 5-digit numeric PINs."
    )
    p.add_argument("hash", nargs="?", help="bcrypt hash (or pipe via stdin)")
    p.add_argument("-w", "--workers", type=int, default=1,
                   help="number of worker processes (default 1)")
    p.add_argument("--max-pin", type=int, default=99_999,
                   help="upper bound of keyspace, inclusive (default 99999)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress progress output")
    args = p.parse_args(argv)

    try:
        h = _read_hash_arg(args.hash)
    except SystemExit as e:
        print(e, file=sys.stderr)
        return 2

    try:
        pw, elapsed = crack(h, workers=max(1, args.workers),
                            verbose=not args.quiet, max_pin=args.max_pin)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if pw:
        print(pw)
        return 0
    print("NOT_FOUND", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
