"""The report a person reads.

The text form is the product: it is what ends up in a terminal and in a README.
These tests pin the parts that carry information - every rule id, every piece
of evidence, the grade - and deliberately not the layout.
"""

from __future__ import annotations

import json

from helpers import NOW, load_one

from tlslint.analyze import audit_files
from tlslint.render import render_json, render_report, render_rules
from tlslint.rules import RULES


def _report():
    return audit_files([("expired.pem", load_one("expired.pem")), ("sha1.pem", load_one("sha1.pem"))], now=NOW)


def test_the_grade_is_in_the_header():
    text = render_report(_report())
    assert f"grade {_report().grade}" in text


def test_every_rule_id_appears():
    text = render_report(_report())
    for rule in _report().rule_ids():
        assert rule in text


def test_every_evidence_line_appears():
    report = _report()
    text = render_report(report)
    for finding in report.findings:
        assert finding.evidence.split(",")[0] in text


def test_the_fix_is_printed():
    text = render_report(_report())
    assert "Reissue and automate renewal" in text


def test_a_clean_report_says_so():
    report = audit_files([("good.pem", load_one("good.pem"))], now=NOW)
    assert "nothing found" in render_report(report)


def test_the_certificate_facts_are_printed_before_the_verdicts():
    report = audit_files([("expired.pem", load_one("expired.pem"))], now=NOW)
    text = render_report(report)
    assert text.index("certificate") < text.index("TLS020")


def test_json_round_trips():
    payload = json.loads(render_json(_report()))
    assert payload["findings"]
    assert payload["grade"]
    assert payload["counts"]["critical"] >= 1


def test_json_carries_the_certificate_facts():
    payload = json.loads(render_json(_report()))
    assert payload["certificates"][0]["subject"]
    assert payload["certificates"][0]["signature_algorithm"]


def test_json_is_utf8_safe():
    payload = render_json(_report())
    payload.encode("utf-8").decode("utf-8")


def test_rules_renderer_lists_everything():
    text = render_rules(RULES)
    for rule in RULES:
        assert rule.id in text
        assert rule.title in text


def test_rules_renderer_groups_by_category():
    text = render_rules(RULES)
    assert "certificate" in text
    assert "protocol" in text


def test_the_version_probe_table_is_printed_when_there_is_a_probe():
    from tlslint.analyze import audit_probe
    from tlslint.model import ProbeResult, ProtocolOffer

    probe = ProbeResult(host="h.test", port=443, sni="h.test", protocols=[ProtocolOffer("TLSv1.2", True)])
    text = render_report(audit_probe(probe, now=NOW))
    assert "versions" in text
    assert "TLSv1.2" in text
