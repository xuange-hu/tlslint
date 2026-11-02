"""The shapes everything else moves around."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .x509 import CertFacts

SEVERITIES = ("critical", "high", "medium", "low", "info")

SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    standard: str
    why: str
    fix: str

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]


@dataclass
class Finding:
    """One problem, with the bytes or the wire value that proves it."""

    rule: str
    severity: str
    category: str
    title: str
    where: str  # "cert:good.example.com", "host:example.com:443", "file:..."
    field: str  # the exact field, e.g. "cert.signatureAlgorithm"
    evidence: str
    fix: str
    standard: str = ""

    def key(self) -> tuple[str, str, str]:
        return (self.rule, self.where, self.field)

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "where": self.where,
            "field": self.field,
            "evidence": self.evidence,
            "fix": self.fix,
            "standard": self.standard,
        }


@dataclass
class CipherOffer:
    """One cipher the server was willing to speak."""

    name: str
    protocol: str
    bits: int
    forward_secret: bool
    aead: bool
    mode: str  # "aead" | "cbc" | "stream" | "unknown"
    mac: str  # "sha256" | "sha384" | "sha" | "md5" | ""


@dataclass
class ProtocolOffer:
    version: str  # "SSLv3" | "TLSv1.0" | ...
    offered: bool
    note: str = ""


@dataclass
class Cookie:
    name: str
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[Cookie] = field(default_factory=list)


@dataclass
class HttpProbe:
    https: HttpResponse | None = None
    http: HttpResponse | None = None
    http_location: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class ProbeResult:
    """What the network said. Everything the rules need, nothing they don't."""

    host: str
    port: int
    sni: str
    protocols: list[ProtocolOffer] = field(default_factory=list)
    negotiated_protocol: str | None = None
    negotiated_cipher: str | None = None
    negotiated_bits: int | None = None
    offers: list[CipherOffer] = field(default_factory=list)
    chain: list[CertFacts] = field(default_factory=list)
    chain_kind: str = "unknown"  # "trusted" | "untrusted" | "incomplete" | "unknown"
    chain_error: str | None = None
    http: HttpProbe | None = None
    errors: list[str] = field(default_factory=list)

    def protocol_offered(self, version: str) -> bool:
        for item in self.protocols:
            if item.version == version:
                return item.offered
        return False


@dataclass
class Report:
    target: str
    started: datetime
    hostname: str | None = None
    findings: list[Finding] = field(default_factory=list)
    probe: ProbeResult | None = None
    certificates: list[CertFacts] = field(default_factory=list)
    grade: str = "?"
    notes: list[str] = field(default_factory=list)

    def by_severity(self) -> dict[str, int]:
        counts = dict.fromkeys(SEVERITIES, 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def worst(self) -> str | None:
        if not self.findings:
            return None
        return min(self.findings, key=lambda f: SEVERITY_RANK[f.severity]).severity

    def has(self, rule: str) -> bool:
        return any(f.rule == rule for f in self.findings)

    def rule_ids(self) -> set[str]:
        return {f.rule for f in self.findings}

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "grade": self.grade,
            "started": self.started.isoformat(),
            "counts": self.by_severity(),
            "findings": [f.as_dict() for f in self.findings],
            "notes": self.notes,
        }


# A grade is how most people read a TLS report, so it is computed from the
# findings rather than from a parallel set of thresholds that could disagree.
GRADE_PENALTY = {"critical": 30, "high": 14, "medium": 6, "low": 2, "info": 0}
GRADE_SCALE = [
    (0, "A+"),
    (1, "A"),
    (10, "A-"),
    (20, "B"),
    (35, "C"),
    (50, "D"),
    (70, "E"),
]


def grade_for(findings: list[Finding]) -> str:
    penalty = sum(GRADE_PENALTY[f.severity] for f in findings)
    grade = "F"
    for threshold, letter in GRADE_SCALE:
        if penalty >= threshold:
            grade = letter
    return grade


def rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity, len(SEVERITIES))
