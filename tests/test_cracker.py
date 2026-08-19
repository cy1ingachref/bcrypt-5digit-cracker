"""Tests for the bcrypt 5-digit PIN cracker.

These run quickly because they hash + crack SHORT keyspaces (cost 4, low
max-pin) so the suite finishes in a couple of seconds. They prove the core
guarantee of the tool: a bcrypt hash of a 5-digit numeric PIN is recovered
exactly, and invalid input is rejected cleanly.
"""

import subprocess
import sys

import bcrypt
import pytest

from cracker import crack, cost_of, main


def _hash_pin(pin: str, cost: int = 4) -> str:
    return bcrypt.hashpw(pin.encode(), bcrypt.gensalt(prefix=b"2b", rounds=cost)).decode()


# --------------------------------------------------------------------------
# cost_of
# --------------------------------------------------------------------------
def test_cost_of_parses_known_prefixes():
    assert cost_of("$2a$10$abc") == 10
    assert cost_of("$2b$04$abc") == 4
    assert cost_of("$2y$12$abc") == 12


def test_cost_of_rejects_garbage():
    assert cost_of("not-a-hash") is None
    assert cost_of("$2b$xx$abc") is None


# --------------------------------------------------------------------------
# crack — happy path on tiny keyspaces
# --------------------------------------------------------------------------
@pytest.mark.parametrize("pin", ["00000", "00042", "00123", "99999", "04200"])
def test_crack_recovers_known_pin(pin):
    h = _hash_pin(pin, cost=4)
    found, elapsed = crack(h, workers=1, verbose=False)
    assert found == pin
    assert elapsed >= 0


def test_crack_respects_max_pin():
    # Hash PIN 00099, then crack with max_pin=50 -> should NOT be found.
    h = _hash_pin("00099", cost=4)
    found, _ = crack(h, workers=1, verbose=False, max_pin=50)
    assert found is None


def test_crack_finds_within_max_pin():
    h = _hash_pin("00030", cost=4)
    found, _ = crack(h, workers=1, verbose=False, max_pin=50)
    assert found == "00030"


def test_crack_rejects_invalid_hash():
    with pytest.raises(ValueError):
        crack("clearly-not-bcrypt", verbose=False)


def test_crack_rejects_bad_max_pin():
    with pytest.raises(ValueError):
        crack(_hash_pin("00000", cost=4), verbose=False, max_pin=200_000)


# --------------------------------------------------------------------------
# CLI exit codes (subprocess so we exercise argparse + sys.exit)
# --------------------------------------------------------------------------
def _run(args):
    return subprocess.run(
        [sys.executable, "cracker.py", *args],
        capture_output=True,
        text=True,
    )


def test_cli_finds_pin(tmp_path):
    pin = "00111"
    h = _hash_pin(pin, cost=4)
    r = _run([h])
    assert r.returncode == 0
    assert r.stdout.strip() == pin


def test_cli_not_found(tmp_path):
    # PIN 00060, but clamp the search below it.
    h = _hash_pin("00060", cost=4)
    r = _run([h, "--max-pin", "10", "-q"])
    assert r.returncode == 1


def test_cli_bad_hash():
    r = _run(["not-a-hash"])
    assert r.returncode == 2
    assert "error" in r.stderr.lower()


def test_cli_stdin_hash():
    pin = "00222"
    h = _hash_pin(pin, cost=4)
    r = subprocess.run(
        [sys.executable, "cracker.py"],
        input=h,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0
    assert r.stdout.strip() == pin
