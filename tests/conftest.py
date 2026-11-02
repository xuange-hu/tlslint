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
