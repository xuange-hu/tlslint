"""SARIF 2.1.0 for `github/codeql-action/upload-sarif`.

Rule metadata is emitted once and referenced by index, so a scan of a host with
forty accepted suites does not repeat every description forty times.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import __version__
from .model import Finding, Report
from .rules import BY_ID

__all__ = ["dump", "dumps"]

_SECURITY_SEVERITY = {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "3.0", "info": "1.0"}
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _rules(report: Report) -> tuple[list[dict], dict[str, int]]:
    seen: dict[str, int] = {}
    out: list[dict] = []
    for finding in report.findings:
        if finding.rule in seen:
            continue
        seen[finding.rule] = len(out)
        rule = BY_ID.get(finding.rule)
        title = rule.title if rule else finding.title
        why = rule.why if rule else ""
        fix = rule.fix if rule else finding.fix
        standard = rule.standard if rule else finding.standard
        out.append(
            {
                "id": finding.rule,
                "name": finding.rule,
                "shortDescription": {"text": title},
                "fullDescription": {"text": f"{why} Fix: {fix}"},
                "help": {
                    "text": f"{why}\n\nRemediation: {fix}",
                    "markdown": f"**{title}**\n\n{why}\n\n_Remediation_: {fix}",
                },
                "properties": {
                    "tags": ["security", "tls", "certificate", finding.category],
                    "security-severity": _SECURITY_SEVERITY.get(finding.severity, "1.0"),
                    "standard": standard,
                },
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(finding.severity, "note")},
            }
        )
    return out, seen


def _uri(path: str) -> str:
    """SARIF artifact URIs are forward-slash on every platform.

    Replacing os.sep only fixes the separator of the machine that produced the
    report, so a Windows-style path scanned on Linux kept its backslashes and
    GitHub could not resolve the artifact.
    """
    return path.replace("\\", "/")


def _result(finding: Finding, index_of: dict[str, int]) -> dict:
    return {
        "ruleId": finding.rule,
        "ruleIndex": index_of.get(finding.rule, 0),
        "level": _SARIF_LEVEL.get(finding.severity, "note"),
        "message": {"text": f"{finding.title}: {finding.evidence}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(finding.where), "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": 1, "snippet": {"text": finding.evidence}},
                },
                "logicalLocations": [{"name": finding.field, "kind": "member"}],
            }
        ],
        "properties": {
            "severity": finding.severity,
            "category": finding.category,
            "field": finding.field,
            "standard": finding.standard,
        },
    }


def dumps(report: Report) -> str:
    rules, index_of = _rules(report)
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tlslint",
                        "informationUri": "https://github.com/xuange-hu/tlslint",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "rules": rules,
                    }
                },
                "results": [_result(f, index_of) for f in report.findings],
                "properties": {
                    "tlslint.grade": report.grade,
                    "tlslint.severityCounts": report.by_severity(),
                    "tlslint.target": report.target,
                },
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def dump(report: Report, path: str) -> None:
    # encoding is explicit: the Windows default is cp1252 and rule text is UTF-8
    Path(path).write_text(dumps(report) + "\n", encoding="utf-8")
