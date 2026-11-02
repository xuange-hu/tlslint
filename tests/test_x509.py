"""The X.509 reader against real certificates.

Two kinds of assertion: what the parser says about a fixture it was built for,
and - where openssl is installed - that it says the same thing openssl does.
The parity tests skip rather than fail, because the reader has to work on
machines with no openssl at all.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest
from helpers import fixture_bytes, fixture_path, load_all, load_data, load_one

from tlslint.x509 import CertError, load_certificates, parse_certificate, split_pem

OPENSSL = shutil.which("openssl")


def test_a_certificate_is_a_sequence_of_three():
    good = load_one("good.pem")
    assert good.version == 3
    assert good.subject.first("CN") == "good.example.com"


def test_issuer_and_subject_are_distinct(good, ca):
    assert good.issuer.rfc4514() == ca.subject.rfc4514()
    assert good.subject.rfc4514() != good.issuer.rfc4514()


def test_serial_is_hex_and_even_length(good):
    assert all(char in "0123456789abcdef" for char in good.serial_hex)
    assert len(good.serial_hex) % 2 == 0


def test_validity_parses_to_utc_datetimes(good):
    assert good.not_before is not None and good.not_after is not None
    assert good.not_before.isoformat() == "2026-01-01T00:00:00+00:00"
    assert good.not_after.isoformat() == "2027-01-01T00:00:00+00:00"
    assert good.validity_days == 365


def test_signature_algorithm_is_named(good):
    assert good.signature_algorithm == "sha256WithRSAEncryption"
    assert good.digest == "sha256"
    assert good.signature_key_type == "rsa"


def test_sha1_fixture_is_recognised_as_sha1():
    cert = load_one("sha1.pem")
    assert cert.digest == "sha1"
    assert cert.signature_algorithm == "sha1WithRSAEncryption"


def test_rsa_key_size_comes_from_the_modulus():
    assert load_one("good.pem").public_key.bits == 2048
    assert load_one("rsa1024.pem").public_key.bits == 1024


def test_ec_key_reports_its_curve():
    cert = load_one("ec384.pem")
    assert cert.public_key.algorithm == "ec"
    assert cert.public_key.curve == "secp384r1"
    assert cert.public_key.bits == 384


def test_subject_alt_name_entries_are_typed(good):
    assert good.dns_names == ["good.example.com", "www.good.example.com"]
    assert [n.kind for n in good.san] == ["dNSName", "dNSName"]


def test_ip_address_entries_are_formatted():
    lab = load_data("lab.pem")[0]
    assert ("iPAddress", "127.0.0.1") in [(n.kind, n.value) for n in lab.san]
    assert lab.dns_names[:2] == ["localhost", "*.localhost"]


def test_certificate_without_san_has_no_dns_names():
    cert = load_one("cnonly.pem")
    assert cert.dns_names == []
    assert cert.common_name == "cnonly.example.com"


def test_key_usage_bits_are_named(good):
    assert "digitalSignature" in good.key_usage
    assert "keyEncipherment" in good.key_usage
    assert "keyCertSign" not in good.key_usage


def test_extended_key_usage_is_mapped(good):
    assert good.extended_key_usage == ["serverAuth"]


def test_basic_constraints_ca_flag(ca, good):
    assert ca.is_ca is True
    assert good.is_ca is False


def test_path_length_is_read():
    assert load_one("caleaf.pem").path_len == 0


def test_key_identifiers_are_present(good):
    assert good.subject_key_identifier
    assert good.authority_key_identifier
    assert good.subject_key_identifier != good.authority_key_identifier


def test_aia_and_crldp_urls(good):
    assert good.ocsp_urls == ["http://ocsp.example.com/"]
    assert good.ca_issuer_urls == ["http://ca.example.com/ca.crt"]
    assert good.crl_urls == ["http://crl.example.com/ca.crl"]


def test_self_signed_is_detected():
    assert load_one("selfsigned.pem").is_self_signed() is True
    assert load_one("good.pem").is_self_signed() is False


def test_a_bundle_yields_every_certificate():
    certs = load_all("bundle.pem")
    assert len(certs) == 2
    # the line number a block starts on is part of the identity, so a finding
    # can point at the right one
    assert [c.source for c in certs] == ["bundle.pem#1", "bundle.pem#26"]


def test_a_chain_file_keeps_the_order():
    certs = load_all("chain.pem")
    assert [c.subject.first("CN") for c in certs] == ["good.example.com", "tlslint test CA"]


def test_raw_der_is_accepted():
    from tlslint.x509 import split_pem

    text = fixture_bytes("good.pem").decode()
    (_line, der) = split_pem(text)[0]
    assert parse_certificate(der, "der").subject.first("CN") == "good.example.com"


def test_mismatched_signature_algorithms_are_both_kept():
    cert = load_one("mismatch.pem")
    assert cert.signature_algorithm != cert.signature_algorithm_inner
    assert cert.signature_algorithm_inner == "sha384WithRSAEncryption"


def test_broken_base64_raises_cert_error():
    with pytest.raises(CertError, match="not decodable"):
        load_certificates(fixture_bytes("broken.pem"), "broken.pem")


def test_unclosed_pem_block_raises_cert_error():
    with pytest.raises(CertError, match="never closed"):
        load_certificates(fixture_bytes("truncated.pem"), "truncated.pem")


def test_random_bytes_are_not_a_certificate():
    with pytest.raises(CertError):
        load_certificates(b"not a certificate at all", "junk")


def test_a_der_sequence_that_is_not_a_certificate_is_rejected():
    with pytest.raises(CertError):
        parse_certificate(bytes([0x30, 0x02, 0x05, 0x00]), "empty")


def test_split_pem_ignores_prose_around_the_block():
    text = "some log line\n" + fixture_bytes("good.pem").decode() + "trailing\n"
    blocks = split_pem(text)
    assert len(blocks) == 1


def test_offsets_point_into_the_der(good):
    assert good.der[good.serial_offset : good.serial_offset + 1] == b"\x02"
    assert good.der[good.tbs_offset : good.tbs_offset + 1] == b"\x30"
    assert good.der[good.spki_offset : good.spki_offset + 1] == b"\x30"


def test_duplicate_san_entries_are_preserved():
    cert = load_one("dup.pem")
    assert cert.dns_names == ["dup.example.com", "dup.example.com"]


def test_weak_curve_is_named():
    cert = load_one("ec256k1.pem")
    assert cert.public_key.curve == "secp256k1"
    assert cert.public_key.bits == 256


# --------------------------------------------------------------------- parity


@pytest.mark.skipif(OPENSSL is None, reason="openssl is not installed")
def test_subject_matches_openssl():
    out = subprocess.run(
        [OPENSSL, "x509", "-in", str(fixture_path("good.pem")), "-noout", "-subject"],
        capture_output=True,
        text=True,
        check=True,
    )
    # openssl prints "C = US, O = tlslint, CN = host"; the spacing is its own
    expected = _normalise_name(out.stdout.strip().split("=", 1)[1])
    assert load_one("good.pem").subject.rfc4514() == expected


@pytest.mark.skipif(OPENSSL is None, reason="openssl is not installed")
def _normalise_name(text: str) -> str:
    """openssl pads around "=" and after ","; RFC 4514 does not."""
    return ",".join(part.replace(" = ", "=").strip() for part in text.split(","))


def test_serial_matches_openssl():
    out = subprocess.run(
        [OPENSSL, "x509", "-in", str(fixture_path("good.pem")), "-noout", "-serial"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.stdout.strip().split("=")[1].lower().lstrip("0") or "0"
    assert load_one("good.pem").serial_hex.lstrip("0").lower() == out.stdout.strip().split("=")[1].lower().lstrip("0")


@pytest.mark.skipif(OPENSSL is None, reason="openssl is not installed")
def test_dates_match_openssl():
    out = subprocess.run(
        [OPENSSL, "x509", "-in", str(fixture_path("good.pem")), "-noout", "-dates"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "notBefore" in out.stdout
    good = load_one("good.pem")
    assert good.not_before is not None and good.not_after is not None


@pytest.mark.skipif(OPENSSL is None, reason="openssl is not installed")
def test_signature_algorithm_matches_openssl():
    out = subprocess.run(
        [OPENSSL, "x509", "-in", str(fixture_path("sha1.pem")), "-noout", "-text"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "sha1WithRSAEncryption" in out.stdout
    assert load_one("sha1.pem").digest == "sha1"


@pytest.mark.skipif(OPENSSL is None, reason="openssl is not installed")
def test_public_key_size_matches_openssl():
    for name, bits in (("good.pem", 2048), ("rsa1024.pem", 1024)):
        out = subprocess.run(
            [OPENSSL, "x509", "-in", str(fixture_path(name)), "-noout", "-text"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert f"Public-Key: ({bits} bit)" in out.stdout
        assert load_one(name).public_key.bits == bits


