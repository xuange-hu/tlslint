"""SARIF output, checked the way a consumer would read it."""

from __future__ import annotations

import json
from pathlib import Path

from helpers import NOW, load_one

from tlslint.analyze import audit_files
from tlslint.sarif import dump, dumps


def _report():
    return audit_files([("expired.pem", load_one("expired.pem")), ("sha1.pem", load_one("sha1.pem"))], now=NOW)


def test_version_and_schema():
    payload = json.loads(dumps(_report()))
    assert payload["version"] == "2.1.0"
    assert payload["$schema"].startswith("https://json.schemastore.org/sarif-2.1.0")


def test_rules_are_declared_once_and_referenced_by_index():
    payload = json.loads(dumps(_report()))
    run = payload["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))
    for result in run["results"]:
        index = result["ruleIndex"]
        assert rules[index]["id"] == result["ruleId"]


def test_every_result_carries_a_severity_and_a_location():
    payload = json.loads(dumps(_report()))
    for result in payload["runs"][0]["results"]:
        assert result["level"] in {"error", "warning", "note"}
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_security_severity_is_a_number_github_understands():
    payload = json.loads(dumps(_report()))
    for rule in payload["runs"][0]["tool"]["driver"]["rules"]:
        value = float(rule["properties"]["security-severity"])
        assert 0.0 < value <= 10.0


def test_uris_use_forward_slashes_even_for_windows_paths(tmp_path: Path):
    report = audit_files([("expired.pem", load_one("expired.pem"))], now=NOW)
    report.findings[0].where = "file:C:\\certs\\leaf.pem"
    payload = json.loads(dumps(report))
    uri = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "\\" not in uri


def test_the_grade_and_counts_are_in_the_properties():
    payload = json.loads(dumps(_report()))
    props = payload["runs"][0]["properties"]
    assert props["tlslint.grade"]
    assert "critical" in props["tlslint.severityCounts"]


def test_dump_writes_utf8(tmp_path: Path):
    path = tmp_path / "results.sarif"
    dump(_report(), str(path))
    # reading with the platform default would be wrong on Windows; utf-8 is the
    # only encoding rule text can be written in
    text = path.read_text(encoding="utf-8")
    assert json.loads(text)["version"] == "2.1.0"


def test_an_empty_report_is_still_valid_sarif():
    payload = json.loads(dumps(audit_files([("good.pem", load_one("good.pem"))], now=NOW)))
    assert payload["runs"][0]["results"] == []
    assert payload["runs"][0]["tool"]["driver"]["rules"] == []
