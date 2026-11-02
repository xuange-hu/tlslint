"""Output. The text form is the one a person reads, so it is the one that has
to make the evidence obvious: every finding carries the field and the value it
came from, and the certificate facts are printed before the verdicts that use
them.
"""

from __future__ import annotations

import json

from . import __version__
from .model import SEVERITIES, Finding, Report, Rule
from .rules import CATEGORIES
from .x509 import CertFacts

SEVERITY_MARK = {
    "critical": "!!",
    "high": "! ",
    "medium": "~ ",
    "low": "- ",
    "info": "  ",
}

BAR_WIDTH = 60


def _rule_line(finding: Finding) -> str:
    mark = SEVERITY_MARK.get(finding.severity, "  ")
    return f"  {mark}{finding.rule}  {finding.title}"


def render_finding(finding: Finding, width: int = 88) -> list[str]:
    lines = [_rule_line(finding)]
    lines.append(f"      where  {finding.where} :: {finding.field}")
    lines.append(f"      saw    {finding.evidence}")
    lines.append(f"      fix    {finding.fix}")
    if finding.standard:
        lines.append(f"      std    {finding.standard}")
    return lines


def render_report(report: Report, color: bool = False) -> str:
    lines: list[str] = []
    lines.append(f"tlslint {__version__}  {report.target}")
    lines.append("")
    counts = report.by_severity()
    shown = "  ".join(f"{name} {counts[name]}" for name in SEVERITIES if counts[name])
    lines.append(f"grade {report.grade}    {len(report.findings)} finding(s)   {shown or 'clean'}")
    lines.append("")

    if report.notes:
        for note in report.notes:
            lines.append(f"  . {note}")
        lines.append("")

    for cert in report.certificates[:1]:
        lines += render_certificate(cert)

    probe = report.probe
    if probe is not None:
        lines += render_versions(probe)
        if probe.offers:
            lines.append("  suites accepted")
            for offer in sorted(probe.offers, key=lambda o: (-o.bits, o.name))[:12]:
                flag = "AEAD" if offer.aead else offer.mode
                fs = "FS" if offer.forward_secret else "no-FS"
                lines.append(f"    {offer.name:<40} {offer.protocol:<8} {offer.bits:>4}-bit  {flag:<7} {fs}")
            if len(probe.offers) > 12:
                lines.append(f"    ... and {len(probe.offers) - 12} more")
            lines.append("")

    if not report.findings:
        lines.append("  nothing found")
        lines.append("")
        return "\n".join(lines)

    for severity in SEVERITIES:
        group = [f for f in report.findings if f.severity == severity]
        if not group:
            continue
        lines.append(f"  {severity.upper()}")
        for finding in group:
            lines += render_finding(finding)
        lines.append("")
    return "\n".join(lines)


def render_certificate(cert: CertFacts) -> list[str]:
    lines = ["  certificate"]
    lines.append(f"    subject   {cert.subject.rfc4514()}")
    lines.append(f"    issuer    {cert.issuer.rfc4514()}")
    lines.append(f"    serial    {cert.serial_hex}")
    lines.append(f"    validity  {cert.not_before_text} .. {cert.not_after_text}")
    if cert.validity_days is not None:
        lines[-1] += f"  ({cert.validity_days} days)"
    key = cert.public_key
    curve = f" {cert.public_key.curve}" if key.curve else ""
    lines.append(f"    key       {key.algorithm}{curve} {key.bits} bits")
    lines.append(f"    signature {cert.signature_algorithm}")
    if cert.dns_names:
        lines.append(f"    names     {', '.join(cert.dns_names[:5])}")
    else:
        lines.append(f"    names     <none in subjectAltName; CN={cert.common_name}>")
    lines.append("")
    return lines


def render_versions(probe) -> list[str]:
    lines = ["  versions"]
    for offer in probe.protocols:
        mark = "accepted" if offer.offered else "refused "
        extra = f"  ({offer.note})" if offer.note and not offer.offered else ""
        lines.append(f"    {offer.version:<8} {mark}{extra}")
    lines.append("")
    return lines


def render_rules(rules: list[Rule]) -> str:
    lines: list[str] = []
    by_category: dict[str, list[Rule]] = {}
    for rule in rules:
        by_category.setdefault(rule.category, []).append(rule)
    for category, items in by_category.items():
        lines.append(f"  {category}  ({CATEGORIES.get(category, '')})")
        for rule in items:
            lines.append(f"    {rule.id}  [{rule.severity:<8}] {rule.title}")
            lines.append(f"             {rule.standard}")
        lines.append("")
    return "\n".join(lines)


def render_json(report: Report) -> str:
    payload = report.as_dict()
    payload["version"] = __version__
    payload["certificates"] = [certificate_as_dict(c) for c in report.certificates]
    if report.probe is not None:
        payload["probe"] = {
            "host": report.probe.host,
            "port": report.probe.port,
            "sni": report.probe.sni,
            "protocol": report.probe.negotiated_protocol,
            "cipher": report.probe.negotiated_cipher,
            "bits": report.probe.negotiated_bits,
            "versions": [{"version": o.version, "offered": o.offered, "note": o.note} for o in report.probe.protocols],
            "suites": [
                {
                    "name": o.name,
                    "protocol": o.protocol,
                    "bits": o.bits,
                    "forward_secret": o.forward_secret,
                    "aead": o.aead,
                    "mode": o.mode,
                    "mac": o.mac,
                }
                for o in report.probe.offers
            ],
            "chain_kind": report.probe.chain_kind,
        }
    return json.dumps(payload, indent=2, sort_keys=False)


def certificate_as_dict(cert: CertFacts) -> dict:
    return {
        "source": cert.source,
        "subject": cert.subject.rfc4514(),
        "issuer": cert.issuer.rfc4514(),
        "serial": cert.serial_hex,
        "not_before": cert.not_before_text,
        "not_after": cert.not_after_text,
        "validity_days": cert.validity_days,
        "signature_algorithm": cert.signature_algorithm,
        "public_key": {
            "algorithm": cert.public_key.algorithm,
            "bits": cert.public_key.bits,
            "curve": cert.public_key.curve,
        },
        "dns_names": cert.dns_names,
        "is_ca": cert.is_ca,
        "key_usage": cert.key_usage,
        "extended_key_usage": cert.extended_key_usage,
        "ocsp": cert.ocsp_urls,
        "crl": cert.crl_urls,
        "sct": cert.sct_count,
        "self_signed": cert.is_self_signed(),
        "extensions": sorted(cert.extensions),
    }
