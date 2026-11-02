"""`tlslint demo`: a complete scan with no network access.

It starts five local servers, each wrong in a different way, reads the shipped
certificate fixtures, and merges the two into one report. The point is that the
demo is reproducible: it does not depend on somebody else's server still being
configured the way it was when the assertion was written, and it does not
depend on the local OpenSSL still offering RC4 (none of them do).

The certificate rules are judged against a fixed clock, because a fixture that
expires "in 25 days" has to mean the same thing next year.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import lab
from .analyze import audit_certificate, audit_probe
from .model import Finding, Report, grade_for
from .probe import probe
from .x509 import load_certificates

# Every fixture is dated around this instant, so "expires in 25 days" stays
# true however long the repository sits on a shelf.
FIXED_NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)

DATA = Path(__file__).parent / "data"
DEMO_CERTS = DATA / "demo"

# Each server exercises a different family of findings.
SERVERS = ("weak", "legacy", "tls13", "aes128", "mismatched")

# A hostname no certificate here covers, so the name-matching rule has
# something to report.
UNCOVERED = "cnonly.example.com"


@dataclass
class DemoResult:
    servers: list[tuple[str, str, Report]] = field(default_factory=list)
    offline: list[tuple[str, list[Finding]]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def grade(self) -> str:
        return grade_for(self.findings)

    def rule_ids(self) -> set[str]:
        return {f.rule for f in self.findings}


def certificate_findings(now: datetime = FIXED_NOW) -> list[tuple[str, list[Finding]]]:
    """The shipped certificates, read with no connection at all."""
    out: list[tuple[str, list[Finding]]] = []
    if not DEMO_CERTS.is_dir():
        return out
    for path in sorted(DEMO_CERTS.glob("*.pem")):
        try:
            certs = load_certificates(path.read_bytes(), source=path.name)
        except ValueError:
            continue
        # Only the certificate with no subjectAltName is given a hostname to
        # match: that is where "the name is unverifiable" and "the name does
        # not match" are both worth showing.
        hostname = UNCOVERED if path.name == "cnonly.pem" else None
        for cert in certs:
            out.append((path.name, audit_certificate(cert, where=f"file:{path.name}", hostname=hostname, now=now)))
    return out


def server_findings(profile: str, timeout: float = 6.0) -> tuple[str, str, Report]:
    server = lab.start(lab.LabConfig(profile=profile))
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
        return profile, server.target, audit_probe(result, now=FIXED_NOW)
    finally:
        server.stop()


def run(timeout: float = 6.0, with_servers: bool = True) -> DemoResult:
    demo = DemoResult()
    if with_servers:
        for profile in SERVERS:
            try:
                demo.servers.append(server_findings(profile, timeout=timeout))
            except OSError:  # pragma: no cover - a sandbox without sockets
                continue
    demo.offline = certificate_findings()

    seen: set[tuple[str, str, str]] = set()
    for _profile, _target, report in demo.servers:
        for finding in report.findings:
            key = finding.key()
            if key not in seen:
                seen.add(key)
                demo.findings.append(finding)
    for _name, findings in demo.offline:
        for finding in findings:
            key = finding.key()
            if key not in seen:
                seen.add(key)
                demo.findings.append(finding)
    demo.findings.sort(key=lambda f: (f.rule, f.where))
    return demo


def as_report(demo: DemoResult) -> Report:
    report = Report(target="demo", started=FIXED_NOW, findings=demo.findings)
    report.grade = demo.grade
    report.notes = [
        f"{len(demo.servers)} local server(s): " + ", ".join(sorted(p for p, _, _ in demo.servers)),
        f"{len(demo.offline)} certificate(s) read from disk",
        f"judged against a fixed clock ({FIXED_NOW.date().isoformat()}) so the fixtures cannot expire",
        "no connection left the machine",
    ]
    return report
