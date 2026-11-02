"""MCP server: the same audit, callable from Claude Code, Cursor or Cline.

The tool bodies are plain module-level functions, so they are testable with no
optional dependency installed; only ``build_server`` needs ``mcp``, and it
imports it lazily. ``TOOLS`` is the registry that both the server and the tests
read, so the two cannot disagree about what is exposed.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import demo as demo_mod
from .analyze import audit_files, audit_probe
from .model import SEVERITIES
from .probe import probe, split_host
from .render import render_json, render_report, render_rules
from .rules import BY_ID, RULES, rules_for
from .sarif import dumps as sarif_dumps
from .x509 import CertError, load_certificates

__all__ = ["TOOLS", "build_server", "main"]


def tlslint_scan(target: str, timeout: float = 6.0, quick: bool = False, as_json: bool = False) -> str:
    """Audit a TLS server. target is host, host:port or [ipv6]:port.

    quick asks for versions and the certificate only: one handshake per version
    instead of one per candidate cipher suite.
    """
    host, port = split_host(target)
    result = probe(host, port, timeout=timeout, deep=not quick)
    report = audit_probe(result)
    return render_json(report) if as_json else render_report(report)


def tlslint_cert(path: str, hostname: str = "", as_json: bool = False) -> str:
    """Audit a certificate file (PEM, PEM bundle or DER) with no network access.

    Pass hostname to also check that the name is covered by the certificate.
    """
    target = Path(path)
    if not target.is_file():
        return f"no such file: {path}"
    try:
        certs = load_certificates(target.read_bytes(), source=str(target))
    except CertError as exc:
        return f"could not read {path}: {exc}"
    hostnames = {str(target): hostname} if hostname else {}
    report = audit_files([(str(target), cert) for cert in certs], hostnames=hostnames)
    return render_json(report) if as_json else render_report(report)


def tlslint_rules(category: str = "", severity: str = "") -> str:
    """List the rules, optionally filtered by category or severity."""
    selected = rules_for(category or None, severity or None)
    return f"{len(selected)} of {len(RULES)} rules\n\n" + render_rules(selected)


def tlslint_explain(rule_id: str) -> str:
    """Explain one rule: what it means, why it matters, and the fix."""
    rule = BY_ID.get(rule_id.upper())
    if rule is None:
        return f"unknown rule {rule_id!r}. Known rules: " + ", ".join(sorted(BY_ID))
    return "\n".join(
        [
            f"{rule.id} [{rule.severity}] {rule.title}",
            f"category: {rule.category}",
            f"standard: {rule.standard}",
            f"why:      {rule.why}",
            f"fix:      {rule.fix}",
        ]
    )


def tlslint_grade(target: str, timeout: float = 6.0, fail_on: str = "") -> str:
    """Grade and severity counts for one target.

    Set fail_on to a severity (critical, high, medium, low, info) to also get
    the verdict a CI gate would use.
    """
    host, port = split_host(target)
    report = audit_probe(probe(host, port, timeout=timeout))
    payload = {
        "target": report.target,
        "grade": report.grade,
        "counts": report.by_severity(),
        "rules": sorted(report.rule_ids()),
    }
    if fail_on and fail_on in SEVERITIES:
        worst = report.worst()
        payload["fail_on"] = fail_on
        payload["passes"] = not (worst is not None and SEVERITIES.index(worst) <= SEVERITIES.index(fail_on))
    return json.dumps(payload, indent=2)


def tlslint_demo(as_json: bool = False) -> str:
    """Run the offline demo: local servers plus the shipped certificates."""
    report = demo_mod.as_report(demo_mod.run())
    return render_json(report) if as_json else render_report(report)


def tlslint_sarif(target: str, path: str, timeout: float = 6.0) -> str:
    """Scan a target and write a SARIF 2.1.0 report to path."""
    host, port = split_host(target)
    report = audit_probe(probe(host, port, timeout=timeout))
    # encoding is explicit: rule text is UTF-8 and the Windows default is cp1252
    Path(path).write_text(sarif_dumps(report) + "\n", encoding="utf-8")
    return f"wrote {len(report.findings)} finding(s) to {path} (grade {report.grade})"


TOOLS = (
    tlslint_scan,
    tlslint_cert,
    tlslint_rules,
    tlslint_explain,
    tlslint_grade,
    tlslint_demo,
    tlslint_sarif,
)


def build_server():
    from mcp.server.fastmcp import FastMCP

    # Only the name is passed: FastMCP has gained and dropped keyword arguments
    # across 1.x, and `version` is one it dropped.
    mcp = FastMCP(name="tlslint")
    for tool in TOOLS:
        mcp.tool(name=tool.__name__)(tool)
    return mcp


def main() -> None:
    build_server().run()


if __name__ == "__main__":  # pragma: no cover
    main()
