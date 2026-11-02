"""A fresh clone must be able to run `pytest` with nothing installed.

The src/ layout means the package is not importable on a contributor's machine
unless something puts src/ on sys.path - that is what the root conftest.py
does. CI never notices it disappearing because CI runs `pip install -e .`
first.
"""

from __future__ import annotations

import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_root_conftest_bootstraps_src():
    path = os.path.join(REPO_ROOT, "conftest.py")
    assert os.path.isfile(path)
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    assert "sys.path" in text and "src" in text


def test_pytest_collects_without_the_package_installed():
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "--collect-only", "-q", "-o", "addopts="],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "::" in proc.stdout, out


def test_the_shipped_data_files_exist():
    """The lab and the demo read these at run time, not from tests/."""
    data = os.path.join(REPO_ROOT, "src", "tlslint", "data")
    for name in ("lab.pem", "lab.key", "mismatched.pem"):
        assert os.path.isfile(os.path.join(data, name)), name
    assert os.path.isdir(os.path.join(data, "demo"))
