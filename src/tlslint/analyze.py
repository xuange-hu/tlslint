"""Turning facts into findings.

Two passes, and the second one is where the interesting results come from:

1. one certificate at a time (or one probe result at a time);
2. relationships: the hostname against the names the certificate claims, the
   leaf against the chain it arrived with, and the HTTP answer against the TLS
   connection underneath it.

Nothing is reported without the value that proves it, and nothing is inferred
from a version banner.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime

from .model import (
    CipherOffer,
    Finding,
    ProbeResult,
    Report,
    grade_for,
)
from .rules import BY_ID, CERTIFICATE, CIPHER, PROTOCOL, TRANSPORT
from .x509 import CertFacts, utcnow

WEAK_SUITE_MARKERS = ("NULL", "EXPORT", "LOW", "eNULL", "aNULL", "IDEA", "SEED", "PSK", "DES-CBC3-SHA")
BROKEN_SUITE_MARKERS = ("NULL", "EXP", "eNULL", "aNULL", "LOW", "IDEA")

MIN_KEY_BITS = 2048
MIN_EC_BITS = 256
MAX_VALIDITY_DAYS = 398
EXPIRY_WARNING_DAYS = 30
HSTS_MIN_AGE = 15552000  # 180 days, the floor hstspreload.org accepts


def _finding(rule_id: str, where: str, field: str, evidence: str) -> Finding:
    rule = BY_ID[rule_id]
    return Finding(
        rule=rule.id,
        severity=rule.severity,
        category=rule.category,
        title=rule.title,
        where=where,
        field=field,
        evidence=evidence,
        fix=rule.fix,
        standard=rule.standard,
    )


def covers(cert: CertFacts, hostname: str) -> bool:
    """RFC 6125 matching: exact, or one wildcard label, or an address entry."""
    host = hostname.strip().rstrip(".").lower()
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for name in cert.san:
        if name.kind == "iPAddress" and address is not None:
            try:
                if ipaddress.ip_address(name.value) == address:
                    return True
            except ValueError:
                continue
        elif name.kind != "dNSName" or address is not None:
            continue
        else:
            value = name.value.strip().rstrip(".").lower()
            if value == host:
                return True
            if value.startswith("*."):
                tail = value[2:]
                head = host[: -len(tail) - 1] if host.endswith("." + tail) else ""
                # A wildcard covers exactly one label: *.example.com covers
                # a.example.com, never example.com and never a.b.example.com.
                if head and "." not in head and host.endswith("." + tail):
                    return True
    return False


def _names_claimed(cert: CertFacts) -> str:
    dns = cert.dns_names
    if dns:
        return ", ".join(dns[:4]) + (f" (+{len(dns) - 4})" if len(dns) > 4 else "")
    cn = cert.common_name
    return f"commonName={cn}" if cn else "<no name at all>"


def audit_certificate(
    cert: CertFacts,
    where: str = "cert",
    hostname: str | None = None,
    now: datetime | None = None,
    role: str = "leaf",
) -> list[Finding]:
    """One certificate, read on its own."""
    now = now or utcnow()
    out: list[Finding] = []
    is_leaf = role == "leaf"

    def add(rule_id: str, field: str, evidence: str) -> None:
        out.append(_finding(rule_id, where, field, evidence))

    if cert.signature_algorithm != cert.signature_algorithm_inner:
        add(
            "TLS038",
            "cert.signatureAlgorithm",
            f"tbsCertificate.signature={cert.signature_algorithm_inner} "
            f"but Certificate.signatureAlgorithm={cert.signature_algorithm}",
        )

    if cert.not_after is not None:
        days_left = cert.days_left(now)
        if days_left is not None and days_left < 0:
            add(
                "TLS020",
                "cert.notAfter",
                f"notAfter={cert.not_after_text} ({cert.not_after.isoformat()}), {-days_left} days ago",
            )
        elif days_left is not None and days_left <= EXPIRY_WARNING_DAYS:
            add(
                "TLS022",
                "cert.notAfter",
                f"notAfter={cert.not_after_text} ({cert.not_after.isoformat()}), {days_left} days left",
            )

    if cert.not_before is not None and cert.not_before > now:
        add("TLS021", "cert.notBefore", f"notBefore={cert.not_before_text} ({cert.not_before.isoformat()}) is in the future")

    span = cert.validity_days
    if span is not None and span > MAX_VALIDITY_DAYS:
        add("TLS023", "cert.validity", f"{span} days, the public CA limit is {MAX_VALIDITY_DAYS}")

    if cert.digest in {"md5", "md2", "sha1"}:
        add("TLS024", "cert.signatureAlgorithm", f"{cert.signature_algorithm} (digest {cert.digest or 'unknown'})")

    key = cert.public_key
    if key.algorithm in {"rsa", "dsa"} and 0 < key.bits < MIN_KEY_BITS:
        add("TLS025", "cert.subjectPublicKeyInfo", f"{key.algorithm} {key.bits} bits, minimum is {MIN_KEY_BITS}")
    elif key.algorithm == "ec" and 0 < key.bits < MIN_EC_BITS:
        add("TLS025", "cert.subjectPublicKeyInfo", f"EC {key.bits} bits, minimum is {MIN_EC_BITS}")
    if key.curve and key.curve in {"secp192r1", "secp224r1", "secp256k1"}:
        add("TLS039", "cert.subjectPublicKeyInfo", f"curve {key.curve}")

    if is_leaf and "subjectAltName" not in cert.extensions:
        add("TLS026", "cert.extensions", f"no subjectAltName; {_names_claimed(cert)}")
    elif is_leaf and not cert.dns_names and "subjectAltName" in cert.extensions:
        add("TLS026", "cert.subjectAltName", "subjectAltName present but holds no dNSName")

    if is_leaf and hostname and not covers(cert, hostname):
        add("TLS027", "cert.subjectAltName", f"asked for {hostname}; certificate claims {_names_claimed(cert)}")

    wildcards = [n.value for n in cert.san if n.kind == "dNSName" and n.value.startswith("*.")]
    if wildcards:
        add("TLS028", "cert.subjectAltName", ", ".join(wildcards[:3]))

    if cert.is_self_signed():
        add("TLS029", "cert.issuer", f"issuer == subject == {cert.subject.rfc4514()}")

    if is_leaf and not cert.is_self_signed():
        if not cert.ocsp_urls:
            add("TLS032", "cert.authorityInfoAccess", "no OCSP responder in authorityInfoAccess")
        if not cert.crl_urls:
            add("TLS033", "cert.CRLDistributionPoints", "no crlDistributionPoints")

    ku = cert.key_usage
    if is_leaf and ku and not ({"digitalSignature", "keyEncipherment", "keyAgreement"} & set(ku)):
        add("TLS034", "cert.keyUsage", f"keyUsage={','.join(ku)}")

    eku = cert.extended_key_usage
    if is_leaf and eku and "serverAuth" not in eku and "anyExtendedKeyUsage" not in eku:
        add("TLS035", "cert.extendedKeyUsage", f"extendedKeyUsage={','.join(eku)}")

    if is_leaf and cert.is_ca:
        add("TLS036", "cert.basicConstraints", f"basicConstraints CA:TRUE (pathlen={cert.path_len})")

    seen: set[str] = set()
    for name in cert.san:
        tag = f"{name.kind}:{name.value.lower()}"
        if tag in seen:
            add("TLS037", "cert.subjectAltName", f"{name.kind}={name.value} appears more than once")
        seen.add(tag)

    cn = cert.common_name
    if is_leaf and cn and cert.dns_names:
        lowered = {n.lower() for n in cert.dns_names}
        if cn.lower() not in lowered and _looks_like_host(cn):
            add("TLS040", "cert.commonName", f"CN={cn} is not among {', '.join(sorted(lowered)[:3])}")

    return out


def _looks_like_host(value: str) -> bool:
    if not value or " " in value:
        return False
    return "." in value and not value.lower().endswith((".local", ".internal"))


def audit_chain(chain: list[CertFacts], where: str = "chain", chain_kind: str = "unknown") -> list[Finding]:
    """The second pass: what the certificates say about each other."""
    out: list[Finding] = []
    if not chain:
        return out

    if chain_kind == "incomplete":
        leaf = chain[0]
        out.append(
            _finding(
                "TLS030",
                where,
                "chain",
                f"the server sent {len(chain)} certificate(s) and validation stopped with "
                f"'unable to get local issuer certificate' (subject {leaf.subject.rfc4514()})",
            )
        )

    for index in range(len(chain) - 1):
        child, parent = chain[index], chain[index + 1]
        if child.issuer.rfc4514() != parent.subject.rfc4514():
            out.append(
                _finding(
                    "TLS031",
                    where,
                    f"chain[{index}].issuer",
                    f"issuer {child.issuer.rfc4514()} != subject of chain[{index + 1}] {parent.subject.rfc4514()}",
                )
            )
    return out


def audit_protocols(probe: ProbeResult, where: str) -> list[Finding]:
    out: list[Finding] = []
    mapping = {"SSLv3": "TLS001", "TLSv1.0": "TLS002", "TLSv1.1": "TLS003"}
    for offer in probe.protocols:
        rule_id = mapping.get(offer.version)
        if rule_id and offer.offered:
            out.append(_finding(rule_id, where, f"protocol.{offer.version}", f"handshake completed ({offer.note})"))
    if not probe.protocol_offered("TLSv1.2"):
        out.append(_finding("TLS004", where, "protocol.TLSv1.2", "no handshake at TLS 1.2 succeeded"))
    if not probe.protocol_offered("TLSv1.3"):
        out.append(_finding("TLS005", where, "protocol.TLSv1.3", "no handshake at TLS 1.3 succeeded"))
    return out


def _suite_evidence(offers: list[CipherOffer], limit: int = 3) -> str:
    names = [o.name for o in offers[:limit]]
    text = ", ".join(names)
    if len(offers) > limit:
        text += f" (+{len(offers) - limit} more)"
    return text


def audit_ciphers(probe: ProbeResult, where: str) -> list[Finding]:
    out: list[Finding] = []
    offers = probe.offers
    if not offers:
        return out

    def subset(predicate) -> list[CipherOffer]:
        return [o for o in offers if predicate(o)]

    def named(markers: tuple[str, ...]) -> list[CipherOffer]:
        return subset(lambda o: any(marker in o.name.upper() for marker in markers))

    rc4 = named(("RC4",))
    if rc4:
        out.append(_finding("TLS010", where, "cipher.suites", _suite_evidence(rc4)))

    three_des = named(("3DES", "DES-CBC3"))
    if three_des:
        out.append(_finding("TLS011", where, "cipher.suites", _suite_evidence(three_des)))

    broken = named(BROKEN_SUITE_MARKERS)
    if broken:
        out.append(_finding("TLS012", where, "cipher.suites", _suite_evidence(broken)))

    static = subset(lambda o: not o.forward_secret)
    if static:
        out.append(_finding("TLS013", where, "cipher.suites", f"no forward secrecy: {_suite_evidence(static)}"))

    if not subset(lambda o: o.aead):
        out.append(
            _finding(
                "TLS014",
                where,
                "cipher.suites",
                f"none of the {len(offers)} accepted suites is AEAD: {_suite_evidence(offers)}",
            )
        )

    cbc = subset(lambda o: o.mode == "cbc")
    if cbc:
        out.append(_finding("TLS015", where, "cipher.suites", _suite_evidence(cbc)))

    if all(o.bits <= 128 for o in offers):
        out.append(
            _finding("TLS016", where, "cipher.strength", f"strongest accepted suite is {max(o.bits for o in offers)} bits")
        )

    md5 = subset(lambda o: o.mac == "md5")
    if md5:
        out.append(_finding("TLS018", where, "cipher.suites", _suite_evidence(md5)))

    return out


def audit_transport(probe: ProbeResult, host: str, where: str) -> list[Finding]:
    """What the site does around the encrypted connection."""
    out: list[Finding] = []
    if probe.http is None:
        return out

    https = probe.http.https
    if https is not None:
        hsts = https.headers.get("strict-transport-security")
        if hsts is None:
            out.append(
                _finding(
                    "TLS050", where, "header.Strict-Transport-Security", f"HTTPS answer is {https.status} with no HSTS header"
                )
            )
        else:
            age = _max_age(hsts)
            if age is None:
                out.append(_finding("TLS051", where, "header.Strict-Transport-Security", f"{hsts!r} carries no max-age"))
            elif age < HSTS_MIN_AGE:
                out.append(
                    _finding(
                        "TLS051", where, "header.Strict-Transport-Security", f"max-age={age}, floor is {HSTS_MIN_AGE}"
                    )
                )
            if "includesubdomains" not in hsts.lower():
                out.append(_finding("TLS052", where, "header.Strict-Transport-Security", f"{hsts!r} has no includeSubDomains"))
            if "preload" not in hsts.lower():
                out.append(_finding("TLS053", where, "header.Strict-Transport-Security", f"{hsts!r} has no preload"))

    http = probe.http.http
    location = probe.http.http_location
    if http is not None:
        if location is None or not location.lower().startswith("https://"):
            out.append(
                _finding(
                    "TLS054",
                    where,
                    "http.redirect",
                    f"http://{host} answered {http.status}"
                    + (f" and pointed at {location}" if location else " with no redirect"),
                )
            )
        for hop in probe.http.redirect_chain:
            if hop.lower().startswith("http://"):
                out.append(_finding("TLS055", where, "http.redirect", f"the redirect chain goes through {hop}"))

    for source in (https, http):
        if source is None:
            continue
        for cookie in source.cookies:
            label = cookie.name or "<unnamed>"
            if not cookie.secure:
                out.append(_finding("TLS056", where, f"cookie.{label}", "Set-Cookie without Secure"))
            if not cookie.httponly:
                out.append(_finding("TLS057", where, f"cookie.{label}", "Set-Cookie without HttpOnly"))
            if not cookie.samesite:
                out.append(_finding("TLS058", where, f"cookie.{label}", "Set-Cookie without SameSite"))
    return out


def _max_age(header: str) -> int | None:
    for part in header.split(";"):
        key, _, value = part.partition("=")
        if key.strip().lower() == "max-age":
            try:
                return int(value.strip().strip('"'))
            except ValueError:
                return None
    return None


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    out: list[Finding] = []
    for finding in findings:
        key = finding.key()
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def _sorted(findings: list[Finding]) -> list[Finding]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda f: (order.get(f.severity, 9), f.rule, f.where, f.field))


def audit_probe(probe: ProbeResult, now: datetime | None = None) -> Report:
    """Everything one probe result can be read for."""
    now = now or utcnow()
    where = f"host:{probe.host}:{probe.port}"
    findings: list[Finding] = []
    findings += audit_protocols(probe, where)
    findings += audit_ciphers(probe, where)

    for index, cert in enumerate(probe.chain):
        role = "leaf" if index == 0 else "intermediate"
        cert_where = f"{where}/chain[{index}]"
        findings += audit_certificate(
            cert,
            where=cert_where,
            hostname=probe.sni if index == 0 and _is_host(probe.sni) else None,
            now=now,
            role=role,
        )
    findings += audit_chain(probe.chain, where=where, chain_kind=probe.chain_kind)
    findings += audit_transport(probe, probe.host, where)

    findings = _sorted(_dedupe(findings))
    report = Report(target=where, started=now, hostname=probe.sni, findings=findings, probe=probe, certificates=probe.chain)
    report.grade = grade_for(findings)
    report.notes = _notes(probe)
    return report


def _is_host(value: str) -> bool:
    """A bare IP is not a name to match against dNSName."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return True
    return True  # an IP still has to be covered by an iPAddress entry


def _notes(probe: ProbeResult) -> list[str]:
    notes: list[str] = []
    if probe.negotiated_protocol and probe.negotiated_cipher:
        notes.append(
            f"default handshake: {probe.negotiated_protocol} with {probe.negotiated_cipher} "
            f"({probe.negotiated_bits}-bit)"
        )
    offered = [o.version for o in probe.protocols if o.offered]
    notes.append("versions accepted: " + (", ".join(offered) if offered else "none"))
    if probe.offers:
        notes.append(f"{len(probe.offers)} suites accepted; strongest is {max(o.bits for o in probe.offers)} bits")
    else:
        notes.append("suite enumeration produced nothing: the server may refuse single-suite handshakes")
    notes.append(f"chain: {len(probe.chain)} certificate(s), {probe.chain_kind}")
    if probe.chain_error:
        notes.append(f"chain validation said: {probe.chain_error}")
    for error in probe.errors:
        notes.append(f"probe error: {error}")
    return notes


def audit_files(
    certificates: list[tuple[str, CertFacts]],
    hostnames: dict[str, str] | None = None,
    now: datetime | None = None,
) -> Report:
    """Offline: certificates read from disk, with no connection at all."""
    now = now or utcnow()
    hostnames = hostnames or {}
    findings: list[Finding] = []
    for source, cert in certificates:
        where = f"file:{source}"
        findings += audit_certificate(cert, where=where, hostname=hostnames.get(source), now=now)
    findings = _sorted(_dedupe(findings))
    report = Report(target="files", started=now, findings=findings, certificates=[c for _, c in certificates])
    report.grade = grade_for(findings)
    report.notes = [f"{len(certificates)} certificate(s) read from disk, no connection made"]
    return report


CATEGORY_ORDER = [CERTIFICATE, PROTOCOL, CIPHER, TRANSPORT]
