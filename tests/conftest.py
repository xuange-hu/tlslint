"""Shared fixtures.

Every certificate the tests read is a checked-in file, so a test never needs
the network and never needs OpenSSL at run time. The helpers in ``helpers.py``
carry the fixed clock the fixtures were dated around.
"""

from __future__ import annotations

import pytest
from helpers import FIXTURES, NOW, load_all, load_one


@pytest.fixture
def fixtures():
    return FIXTURES


@pytest.fixture
def now():
    return NOW


@pytest.fixture
def good():
    return load_one("good.pem")


@pytest.fixture
def ca():
    return load_one("ca.pem")


@pytest.fixture
def chain():
    return load_all("chain.pem")


def pytest_addoption(parser):
    """``--runslow`` turns the lab tests back on; they are off by default."""
    parser.addoption(
        "--runslow",
        action="store_true",
        default=False,
        help="run tests that start a local TLS server or wait on a closed port",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "slow: starts a local TLS server or waits on a closed port (seconds each)",
    )


def pytest_collection_modifyitems(config, items):
    """Skip ``slow`` unless ``--runslow`` was passed.

    The tests stay in the collection, so the README badge and the badge-check
    job still see all 273; only the default run gets shorter (about 15s instead
    of 156s).
    """
    if config.getoption("--runslow"):
        return
    skip_slow = pytest.mark.skip(reason="needs --runslow")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip_slow)
