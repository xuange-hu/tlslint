"""Test helpers. Lives in tests/ so pytest's rootdir insertion puts it on
sys.path and the test modules can import it without a package.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from tlslint.x509 import load_certificates

FIXTURES = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).resolve().parents[1]

# The instant the fixtures were dated around. It is passed explicitly instead
# of reading the clock, so "expires in 25 days" stays true next year.
NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def fixture_path(name: str) -> Path:
    return FIXTURES / name


def fixture_bytes(name: str) -> bytes:
    return fixture_path(name).read_bytes()


def load_one(name: str):
    return load_certificates(fixture_bytes(name), source=name)[0]


def load_all(name: str):
    return load_certificates(fixture_bytes(name), source=name)


def load_data(name: str):
    return load_certificates((ROOT / "src/tlslint/data" / name).read_bytes(), source=name)
