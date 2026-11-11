"""The rules engine.

The certificate rules are asserted against fixtures, one rule per fixture where
possible, and the rules that cannot be produced by OpenSSL any more (RC4, 3DES,
NULL, MD5) are asserted against hand-built probe results: a scanner has to be
able to name a suite it can no longer negotiate.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from helpers import NOW, load_all, load_one

from tlslint.analyze import (
    audit_certificate,
    audit_chain,
    audit_ciphers,
    audit_files,
    audit_probe,
    audit_protocols,
    covers,
)
from tlslint.model import (
    CipherOffer,
    Cookie,
    Finding,
    HttpProbe,
    HttpResponse,
    ProbeResult,
    ProtocolOffer,
    grade_for,
)
from tlslint.x509 import CertFacts

# (fixture, rule that must fire on it) - the fixture was generated to be wrong
# in exactly that way.
CERT_CASES = [
    ("expired.pem", "TLS020"),
    ("notyet.pem", "TLS021"),
    ("soon.pem", "TLS022"),
    ("long.pem", "TLS023"),
    ("sha1.pem", "TLS024"),
    ("rsa1024.pem", "TLS025"),
    ("cnonly.pem", "TLS026"),
    ("wildcard.pem", "TLS028"),
    ("selfsigned.pem", "TLS029"),
    ("noaia.pem", "TLS032"),
    ("noaia.pem", "TLS033"),
    ("ku.pem", "TLS034"),
    ("clientauth.pem", "TLS035"),
    ("caleaf.pem", "TLS036"),
    ("dup.pem", "TLS037"),
    ("mismatch.pem", "TLS038"),
    ("ec256k1.pem", "TLS039"),
    ("cnsplit.pem", "TLS040"),
]


def rules_of(cert: CertFacts, **kwargs) -> set[str]:
    return {f.rule for f in audit_certificate(cert, **kwargs)}


@pytest.mark.parametrize(("name", "rule"), CERT_CASES)
def test_fixture_fires_the_rule_it_was_built_for(name, rule):
    assert rule in rules_of(load_one(name), where=name, now=NOW)


def test_a_clean_certificate_fires_almost_nothing(good):
    # The one finding left is the wildcard-free, SAN-carrying, CA-issued leaf
    # being judged with no hostname, which is the whole point of a clean scan.
    assert rules_of(good, where="good", now=NOW) == set()


def test_hostname_mismatch_is_critical(good):
    found = rules_of(good, where="good", hostname="elsewhere.example.test", now=NOW)
    assert "TLS027" in found


def test_matching_hostname_is_clean(good):
    assert "TLS027" not in rules_of(good, where="good", hostname="good.example.com", now=NOW)


def test_second_san_name_also_matches(good):
    assert "TLS027" not in rules_of(good, where="good", hostname="www.good.example.com", now=NOW)


def test_wildcard_matches_one_label():
    cert = load_one("wildcard.pem")
    assert covers(cert, "anything.example.com")
    assert not covers(cert, "example.com")
    assert not covers(cert, "a.b.example.com")


def test_case_and_trailing_dot_do_not_matter(good):
    assert covers(good, "GOOD.example.com")
    assert covers(good, "good.example.com.")


def test_ip_address_matching():
    lab = load_all("lab.pem") if False else None
    from helpers import load_data

    lab = load_data("lab.pem")[0]
    assert covers(lab, "127.0.0.1")
    assert not covers(lab, "127.0.0.2")


def test_an_empty_hostname_covers_nothing(good):
    assert not covers(good, "")


def test_validity_window_uses_the_clock_that_was_passed():
    cert = load_one("good.pem")
    # One day before the notBefore: not yet valid. One day after the notAfter:
    # expired. The same certificate, three verdicts, no clock of its own.
    before = datetime(2025, 12, 31, tzinfo=timezone.utc)
    during = NOW
    after = datetime(2027, 1, 2, tzinfo=timezone.utc)
    assert "TLS021" in rules_of(cert, now=before)
    assert rules_of(cert, now=during) == set()
    assert "TLS020" in rules_of(cert, now=after)


def test_expiry_warning_boundary():
    cert = load_one("good.pem")  # notAfter 2027-01-01
    inside = datetime(2026, 12, 15, tzinfo=timezone.utc)  # 17 days
    outside = datetime(2026, 11, 1, tzinfo=timezone.utc)  # 61 days
    assert "TLS022" in rules_of(cert, now=inside)
    assert "TLS022" not in rules_of(cert, now=outside)


def test_intermediates_are_not_held_to_the_server_rules():
    # A CA certificate legitimately has no serverAuth and is marked CA:TRUE.
    ca = load_one("ca.pem")
    as_intermediate = rules_of(ca, where="ca", now=NOW, role="intermediate")
    assert "TLS035" not in as_intermediate
    assert "TLS036" not in as_intermediate
    assert "TLS026" not in as_intermediate


def test_the_same_ca_as_a_leaf_is_reported():
    ca = load_one("ca.pem")
    assert "TLS036" in rules_of(ca, where="ca", now=NOW, role="leaf")


# ------------------------------------------------------------------- the chain


def test_an_incomplete_chain_is_reported():
    chain = [load_one("good.pem")]
    found = audit_chain(chain, where="chain", chain_kind="incomplete")
    assert [f.rule for f in found] == ["TLS030"]


def test_a_complete_chain_is_not_reported():
    chain = load_all("chain.pem")
    assert audit_chain(chain, where="chain", chain_kind="trusted") == []


def test_a_chain_that_does_not_couple_is_reported():
    chain = [load_one("good.pem"), load_one("selfsigned.pem")]
    found = audit_chain(chain, where="chain", chain_kind="trusted")
    assert [f.rule for f in found] == ["TLS031"]
    assert "issuer" in found[0].field


def test_an_empty_chain_produces_nothing():
    assert audit_chain([], where="chain") == []


# ------------------------------------------------------------------- protocols


def _probe(**kwargs) -> ProbeResult:
    return ProbeResult(host="h.test", port=443, sni="h.test", **kwargs)


def test_sslv3_is_critical():
    probe = _probe(protocols=[ProtocolOffer("SSLv3", True), ProtocolOffer("TLSv1.2", True), ProtocolOffer("TLSv1.3", True)])
    assert "TLS001" in {f.rule for f in audit_protocols(probe, "host:h.test:443")}


@pytest.mark.parametrize(("version", "rule"), [("TLSv1.0", "TLS002"), ("TLSv1.1", "TLS003")])
def test_deprecated_versions_are_reported(version, rule):
    probe = _probe(
        protocols=[
            ProtocolOffer(version, True),
            ProtocolOffer("TLSv1.2", True),
            ProtocolOffer("TLSv1.3", True),
        ]
    )
    assert rule in {f.rule for f in audit_protocols(probe, "host:h.test:443")}


def test_a_modern_server_reports_only_the_missing_version():
    probe = _probe(protocols=[ProtocolOffer("TLSv1.2", True), ProtocolOffer("TLSv1.3", True)])
    assert {f.rule for f in audit_protocols(probe, "host:h.test:443")} == set()


def test_missing_tls12_and_tls13_are_both_reported():
    probe = _probe(protocols=[ProtocolOffer("TLSv1.2", False), ProtocolOffer("TLSv1.3", False)])
    assert {f.rule for f in audit_protocols(probe, "host:h.test:443")} == {"TLS004", "TLS005"}


# --------------------------------------------------------------------- ciphers


def offer(name: str, bits: int = 256, forward_secret: bool = True, aead: bool = True, mode: str = "aead", mac: str = "sha256"):
    return CipherOffer(name=name, protocol="TLSv1.2", bits=bits, forward_secret=forward_secret, aead=aead, mode=mode, mac=mac)


def cipher_rules(offers) -> set[str]:
    return {f.rule for f in audit_ciphers(_probe(offers=offers), "host:h.test:443")}


@pytest.mark.parametrize(
    ("name", "rule"),
    [
        ("RC4-SHA", "TLS010"),
        ("ECDHE-RSA-RC4-SHA", "TLS010"),
        ("DES-CBC3-SHA", "TLS011"),
        ("ECDHE-RSA-DES-CBC3-SHA", "TLS011"),
        ("NULL-SHA", "TLS012"),
        ("EXP-RC4-MD5", "TLS012"),
        ("NULL-MD5", "TLS018"),
    ],
)
def test_broken_suites_are_named_even_though_openssl_will_not_negotiate_them(name, rule):
    assert rule in cipher_rules([offer(name, bits=128, forward_secret=False, aead=False, mode="cbc", mac="md5")])


def test_missing_forward_secrecy_is_reported():
    assert "TLS013" in cipher_rules([offer("AES256-SHA", forward_secret=False, aead=False, mode="cbc")])


def test_forward_secrecy_everywhere_is_clean():
    assert "TLS013" not in cipher_rules([offer("ECDHE-RSA-AES256-GCM-SHA384")])


def test_no_aead_anywhere_is_reported():
    assert "TLS014" in cipher_rules([offer("ECDHE-RSA-AES256-SHA384", aead=False, mode="cbc")])


def test_one_aead_suite_is_enough():
    assert "TLS014" not in cipher_rules(
        [offer("ECDHE-RSA-AES256-SHA384", aead=False, mode="cbc"), offer("ECDHE-RSA-AES256-GCM-SHA384")]
    )


def test_cbc_is_reported_alongside_aead():
    assert "TLS015" in cipher_rules([offer("ECDHE-RSA-AES256-SHA384", aead=False, mode="cbc"), offer("ECDHE-RSA-AES256-GCM-SHA384")])


def test_all_128_bit_is_reported():
    assert "TLS016" in cipher_rules([offer("ECDHE-RSA-AES128-GCM-SHA256", bits=128)])


def test_a_256_bit_option_clears_it():
    assert "TLS016" not in cipher_rules([offer("ECDHE-RSA-AES128-GCM-SHA256", bits=128), offer("ECDHE-RSA-AES256-GCM-SHA384")])


def test_no_suites_at_all_is_silent():
    assert cipher_rules([]) == set()


# ---------------------------------------------------------------------- grades


def test_a_clean_report_is_a_plus():
    assert grade_for([]) == "A+"


def test_a_critical_costs_more_than_a_low():
    def finding(severity: str) -> Finding:
        return Finding(rule="TLS999", severity=severity, category="x", title="t", where="w", field="f", evidence="e", fix="x")

    assert grade_for([finding("low")]) == "A"
    assert grade_for([finding("critical")]) == "B"


# --------------------------------------------------------------- file auditing


def test_audit_files_merges_and_dedupes():
    pairs = [(name, load_one(name)) for name in ("expired.pem", "expired.pem")]
    report = audit_files(pairs, now=NOW)
    assert len(report.findings) >= 2
    assert report.target == "files"


def test_audit_files_can_be_given_a_hostname_per_file():
    pairs = [("good.pem", load_one("good.pem"))]
    report = audit_files(pairs, hostnames={"good.pem": "elsewhere.test"}, now=NOW)
    assert "TLS027" in report.rule_ids()

# -- cookies: each attribute judged on its own ---------------------------

def _https_probe(*cookies):
    resp = HttpResponse(status=200, cookies=list(cookies))
    return _probe(http=HttpProbe(https=resp))


def test_a_cookie_without_attributes_is_reported():
    report = audit_probe(_https_probe(Cookie(name="sid")))
    assert {"TLS056", "TLS057", "TLS058"} <= report.rule_ids()


def test_a_fully_attributed_cookie_is_clean_for_the_cookie_rules():
    good = Cookie(name="sid", secure=True, httponly=True, samesite="Lax")
    report = audit_probe(_https_probe(good))
    assert not {"TLS056", "TLS057", "TLS058"} & report.rule_ids()


def test_each_cookie_attribute_is_judged_separately():
    report = audit_probe(_https_probe(Cookie(name="sid", secure=True, httponly=True)))
    ids = report.rule_ids()
    assert "TLS056" not in ids
    assert "TLS057" not in ids
    assert "TLS058" in ids
