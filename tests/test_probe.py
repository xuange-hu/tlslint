"""The parts of the probe that can be tested without a server.

Anything that talks to a socket is covered in test_lab_demo.py. What is left
here is the interpretation: names into properties, bytes into responses, text
into a target.
"""

from __future__ import annotations

import pytest

from tlslint.model import Cookie, HttpProbe, HttpResponse
from tlslint.probe import (
    _classify,
    _parse_cookie,
    _parse_response,
    candidate_ciphers,
    handshake,
    probe_ciphers,
    probe_http,
    probe_protocols,
    read_chain,
    split_host,
    verify_chain,
)


@pytest.mark.parametrize(
    ("value", "host", "port"),
    [
        ("example.com", "example.com", 443),
        ("example.com:8443", "example.com", 8443),
        ("[::1]:8443", "::1", 8443),
        ("[::1]", "::1", 443),
        ("127.0.0.1:443", "127.0.0.1", 443),
    ],
)
def test_split_host(value, host, port):
    assert split_host(value) == (host, port)


def test_split_host_leaves_a_hostname_with_a_colon_but_no_port_alone():
    # "example.com:" is not a port, and neither is a bare IPv6 without brackets
    assert split_host("example.com:")[0] == "example.com:"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("ECDHE-RSA-AES256-GCM-SHA384", (True, True, "aead", "sha384")),
        ("ECDHE-RSA-AES128-GCM-SHA256", (True, True, "aead", "sha256")),
        ("TLS_AES_256_GCM_SHA384", (True, True, "aead", "sha384")),
        ("AES128-SHA", (False, False, "cbc", "sha1")),
        ("AES256-SHA", (False, False, "cbc", "sha1")),
        ("DES-CBC3-SHA", (False, False, "cbc", "sha1")),
        ("ECDHE-RSA-DES-CBC3-SHA", (True, False, "cbc", "sha1")),
        ("RC4-MD5", (False, False, "stream", "md5")),
    ],
)
def test_cipher_classification(name, expected):
    assert _classify(name) == expected


def test_chacha20_is_aead_not_stream():
    # CHACHA20 alone is a stream cipher; CHACHA20-POLY1305 is AEAD
    forward, aead, mode, _mac = _classify("ECDHE-RSA-CHACHA20-POLY1305")
    assert aead is True
    assert mode == "aead"
    assert forward is True


def test_response_parsing():
    payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
        b"Set-Cookie: a=b; Secure; HttpOnly; SameSite=Lax\r\n"
        b"\r\nbody"
    )
    response = _parse_response(payload)
    assert response is not None
    assert response.status == 200
    assert response.headers["strict-transport-security"].startswith("max-age=31536000")
    assert response.cookies[0].secure is True
    assert response.cookies[0].samesite == "Lax"


def test_redirect_parsing():
    payload = b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/\r\n\r\n"
    response = _parse_response(payload)
    assert response.status == 301
    assert response.headers["location"] == "https://example.com/"


def test_a_non_http_answer_is_rejected():
    assert _parse_response(b"garbage\r\n\r\n") is None


def test_an_empty_answer_is_rejected():
    assert _parse_response(b"") is None


def test_a_status_line_without_a_code_is_rejected():
    assert _parse_response(b"HTTP/1.1 OK\r\n\r\n") is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("sid=1; Secure", Cookie(name="sid", secure=True)),
        ("sid=1; HttpOnly", Cookie(name="sid", httponly=True)),
        ("sid=1; SameSite=None", Cookie(name="sid", samesite="None")),
        ("sid=1", Cookie(name="sid")),
        ("sid=1; Path=/; secure", Cookie(name="sid", secure=True)),
    ],
)
def test_cookie_attributes(value, expected):
    parsed = _parse_cookie(value)
    assert (parsed.name, parsed.secure, parsed.httponly, parsed.samesite) == (
        expected.name,
        expected.secure,
        expected.httponly,
        expected.samesite,
    )


def test_candidate_ciphers_is_not_empty():
    # If this is empty the OpenSSL build is unusual, and the suite rules would
    # silently report nothing.
    assert candidate_ciphers()


@pytest.mark.slow
def test_an_unreachable_target_is_reported_not_raised():
    result = handshake("127.0.0.1", 1, "127.0.0.1", timeout=1.0)
    assert result.ok is False
    assert result.error


@pytest.mark.slow
def test_read_chain_on_a_closed_port():
    ders, kind, error = read_chain("127.0.0.1", 1, "127.0.0.1", timeout=1.0)
    assert ders == []
    assert kind in {"unreachable", "untrusted", "unknown"}
    assert error


@pytest.mark.slow
def test_verify_chain_on_a_closed_port():
    kind, error = verify_chain("127.0.0.1", 1, "127.0.0.1", timeout=1.0)
    assert kind in {"unknown", "unreachable", "untrusted"}
    assert error is None or isinstance(error, str)


@pytest.mark.slow
def test_protocol_probe_on_a_closed_port_refuses_everything():
    offers, _errors = probe_protocols("127.0.0.1", 1, "127.0.0.1", timeout=1.0)
    assert offers
    assert all(o.offered is False for o in offers)


@pytest.mark.slow
def test_suite_enumeration_on_a_closed_port_is_empty():
    assert probe_ciphers("127.0.0.1", 1, "127.0.0.1", timeout=1.0, names=["AES128-SHA"], workers=2) == []


@pytest.mark.slow
def test_http_probe_on_a_closed_port_is_empty_and_does_not_raise():
    probe = probe_http("127.0.0.1", 1, plain_port=1, timeout=1.0)
    assert isinstance(probe, HttpProbe)
    assert probe.https is None
    assert probe.http is None


def test_a_probe_result_can_be_built_empty():
    from tlslint.model import ProbeResult

    result = ProbeResult(host="h", port=443, sni="h")
    assert result.protocol_offered("TLSv1.2") is False


def test_an_http_response_defaults_to_no_cookies():
    assert HttpResponse(status=200).cookies == []
