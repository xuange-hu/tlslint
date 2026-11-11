"""The lab servers and the offline demo.

The demo is the thing a visitor runs first, so it has to work with no network
and with whatever OpenSSL is on the machine. That makes an absolute assertion
("rule X fires") fragile: whether TLS 1.0 can still be negotiated depends on
the build. So the contract is written in two halves:

* what the fixtures guarantee, asserted absolutely - a checked-in certificate
  that expired in 2020 expires in 2020 everywhere;
* what the servers guarantee, asserted as consistency - if the probe saw TLS 1.0
  accepted, then the rule that names TLS 1.0 must have fired.
"""

from __future__ import annotations

import pytest

from tlslint import demo as demo_mod
from tlslint import lab as lab_mod
from tlslint.analyze import audit_probe
from tlslint.probe import probe

# Every test in this module starts a lab server or probes one, so the
# whole module is slow: run it with ``pytest --runslow``.
pytestmark = pytest.mark.slow

# Rules the fixtures guarantee, because the clock is fixed and the files are
# checked in.
FIXTURE_RULES = {
    "TLS020",  # expired.pem
    "TLS021",  # notyet.pem
    "TLS022",  # soon.pem
    "TLS023",  # long.pem
    "TLS024",  # sha1.pem
    "TLS025",  # rsa1024.pem
    "TLS026",  # cnonly.pem
    "TLS027",  # cnonly.pem against a hostname it does not carry
    "TLS028",  # wildcard.pem
    "TLS029",  # selfsigned.pem
    "TLS032",  # noaia.pem
    "TLS033",  # noaia.pem
    "TLS034",  # ku.pem
    "TLS035",  # clientauth.pem
    "TLS036",  # caleaf.pem
    "TLS037",  # dup.pem
    "TLS038",  # mismatch.pem
    "TLS039",  # ec256k1.pem
    "TLS040",  # cnsplit.pem
}


def scan_lab(profile: str, timeout: float = 6.0):
    server = lab_mod.start(lab_mod.LabConfig(profile=profile))
    try:
        result = probe(
            server.config.host,
            server.https_port,
            sni="localhost",
            timeout=timeout,
            deep=True,
            with_http=True,
            plain_port=server.http_port,
        )
        return result, audit_probe(result, now=demo_mod.FIXED_NOW)
    finally:
        server.stop()


def test_every_profile_starts_and_stops():
    for profile in lab_mod.PROFILES:
        if profile == "custom":
            continue  # custom keeps the caller's settings and needs a cert file
        server = lab_mod.start(lab_mod.LabConfig(profile=profile))
        try:
            assert server.https_port
            assert server.http_port
            assert server.target.startswith("127.0.0.1:")
        finally:
            server.stop()


def test_a_lab_server_answers_over_tls():
    server = lab_mod.start(lab_mod.LabConfig(profile="modern"))
    try:
        result = probe(server.config.host, server.https_port, sni="localhost", timeout=6.0, deep=False, with_http=False)
        assert result.chain, "the certificate has to be readable for the cert rules to run"
        assert result.negotiated_protocol
    finally:
        server.stop()


def test_the_modern_profile_is_cleaner_than_the_weak_one():
    _modern_probe, modern = scan_lab("modern")
    _weak_probe, weak = scan_lab("weak")
    assert len(modern.findings) < len(weak.findings)


def test_the_modern_profile_offers_no_deprecated_version():
    result, _report = scan_lab("modern")
    assert not result.protocol_offered("TLSv1.0")
    assert not result.protocol_offered("TLSv1.1")


def test_the_weak_profile_ships_the_header_mistakes():
    _result, report = scan_lab("weak")
    assert {"TLS051", "TLS052", "TLS053"} <= report.rule_ids()


def test_the_weak_profile_redirects_through_cleartext():
    result, report = scan_lab("weak")
    assert result.http is not None
    assert any(hop.startswith("http://") for hop in result.http.redirect_chain)
    assert {"TLS054", "TLS055"} <= report.rule_ids()


def test_the_mismatched_profile_redirects_straight_to_https():
    result, report = scan_lab("mismatched")
    assert result.http is not None
    assert result.http.http_location.startswith("https://")
    assert "TLS054" not in report.rule_ids()


def test_a_server_with_no_hsts_is_reported_as_such():
    _result, report = scan_lab("legacy")
    assert "TLS050" in report.rule_ids()


def test_protocol_consistency_whenever_a_version_is_accepted_it_is_reported():
    for profile in ("legacy", "aes128", "tls13", "modern"):
        result, report = scan_lab(profile)
        rules = report.rule_ids()
        for version, rule in (("TLSv1.0", "TLS002"), ("TLSv1.1", "TLS003")):
            if result.protocol_offered(version):
                assert rule in rules, f"{profile}: {version} was accepted but {rule} was not reported"
        if not result.protocol_offered("TLSv1.2"):
            assert "TLS004" in rules, profile
        if not result.protocol_offered("TLSv1.3"):
            assert "TLS005" in rules, profile


def test_cipher_consistency():
    for profile in ("legacy", "aes128", "modern"):
        result, report = scan_lab(profile)
        rules = report.rule_ids()
        if not result.offers:
            continue
        if not any(o.forward_secret for o in result.offers):
            assert "TLS013" in rules, profile
        if not any(o.aead for o in result.offers):
            assert "TLS014" in rules, profile
        if any(o.mode == "cbc" for o in result.offers):
            assert "TLS015" in rules, profile
        if all(o.bits <= 128 for o in result.offers):
            assert "TLS016" in rules, profile


def test_the_aes128_profile_has_no_256_bit_option():
    result, report = scan_lab("aes128")
    assert result.offers, "the lab server must negotiate at least one suite"
    assert all(o.bits <= 128 for o in result.offers)
    assert "TLS016" in report.rule_ids()


def test_the_tls13_profile_strands_tls12_clients():
    result, report = scan_lab("tls13")
    assert result.protocol_offered("TLSv1.3")
    assert not result.protocol_offered("TLSv1.2")
    assert "TLS004" in report.rule_ids()


def test_a_self_signed_lab_certificate_is_reported():
    _result, report = scan_lab("modern")
    assert "TLS029" in report.rule_ids()


# ----------------------------------------------------------------- the demo


def test_the_demo_reads_the_shipped_certificates():
    pairs = demo_mod.certificate_findings()
    assert pairs, "no demo certificates were shipped"
    assert {name for name, _ in pairs} >= {"expired.pem", "sha1.pem", "rsa1024.pem"}


def test_the_demo_fires_every_fixture_rule():
    fired = {f.rule for _name, findings in demo_mod.certificate_findings() for f in findings}
    assert fired >= FIXTURE_RULES, sorted(FIXTURE_RULES - fired)


def test_the_demo_runs_all_of_its_servers():
    result = demo_mod.run()
    assert [profile for profile, _, _ in result.servers] == list(demo_mod.SERVERS)


def test_the_demo_report_carries_the_grade_and_a_note():
    report = demo_mod.as_report(demo_mod.run())
    assert report.grade
    assert any("no connection left the machine" in note for note in report.notes)


def test_the_demo_is_deterministic_about_time():
    # The date a fixture expires is fixed; the clock the demo uses is fixed too,
    # so the same rule fires on every machine and in every year.
    assert demo_mod.FIXED_NOW.year == 2026
    fired = {f.rule for _name, findings in demo_mod.certificate_findings() for f in findings}
    assert "TLS020" in fired
    assert "TLS021" in fired


def test_the_demo_reaches_most_of_the_rule_set():
    result = demo_mod.run()
    total = len({f.rule for f in result.findings})
    assert total >= 30, total
