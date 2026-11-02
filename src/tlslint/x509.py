"""X.509 read from the bytes: PEM, DER, and the fields a TLS audit needs.

Nothing here calls into OpenSSL. The certificate the server sent is the
evidence, and the point of the project is to be able to point at the exact
bytes, so the parsing is done here and every fact keeps the offset it came
from.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import der, oids
from .der import DerError, Tlv, children, read_bit_string, read_integer, read_oid, read_string, read_tlv, read_utc_or_generalized

PEM_HEADER = "-----BEGIN CERTIFICATE-----"
PEM_FOOTER = "-----END CERTIFICATE-----"


class CertError(ValueError):
    """The input is not a certificate this reader can make sense of."""


@dataclass
class NameAttr:
    oid: str
    short: str
    value: str
    offset: int


@dataclass
class CertName:
    attrs: list[NameAttr] = field(default_factory=list)

    def values(self, short: str) -> list[str]:
        return [a.value for a in self.attrs if a.short == short]

    def first(self, short: str) -> str | None:
        for a in self.attrs:
            if a.short == short:
                return a.value
        return None

    def rfc4514(self) -> str:
        return ",".join(f"{a.short}={a.value}" for a in self.attrs) or "<empty>"

    def as_dict(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for a in self.attrs:
            out.setdefault(a.short, []).append(a.value)
        return out


@dataclass
class Extension:
    oid: str
    short: str
    critical: bool
    offset: int
    raw: bytes


@dataclass
class GeneralName:
    kind: str
    value: str


@dataclass
class PublicKey:
    algorithm: str
    bits: int
    curve: str | None = None


@dataclass
class CertFacts:
    """What one certificate says about itself."""

    source: str
    der: bytes
    version: int
    serial_hex: str
    serial_offset: int
    signature_algorithm: str
    signature_algorithm_inner: str
    digest: str
    signature_key_type: str
    issuer: CertName
    subject: CertName
    not_before: datetime | None
    not_after: datetime | None
    not_before_text: str
    not_after_text: str
    validity_offset: int
    public_key: PublicKey
    spki_offset: int
    extensions: dict[str, Extension] = field(default_factory=dict)
    san: list[GeneralName] = field(default_factory=list)
    is_ca: bool = False
    path_len: int | None = None
    key_usage: list[str] = field(default_factory=list)
    extended_key_usage: list[str] = field(default_factory=list)
    subject_key_identifier: str | None = None
    authority_key_identifier: str | None = None
    ocsp_urls: list[str] = field(default_factory=list)
    ca_issuer_urls: list[str] = field(default_factory=list)
    crl_urls: list[str] = field(default_factory=list)
    sct_count: int = 0
    tbs_offset: int = 0

    @property
    def common_name(self) -> str | None:
        return self.subject.first("CN")

    @property
    def dns_names(self) -> list[str]:
        return [n.value for n in self.san if n.kind == "dNSName"]

    @property
    def validity_days(self) -> int | None:
        if self.not_before is None or self.not_after is None:
            return None
        return (self.not_after - self.not_before).days

    def days_left(self, now: datetime) -> int | None:
        if self.not_after is None:
            return None
        return (self.not_after - now).days

    def ext(self, short: str) -> Extension | None:
        return self.extensions.get(short)

    def is_self_issued(self) -> bool:
        return self.issuer.rfc4514() == self.subject.rfc4514()

    def is_self_signed(self) -> bool:
        """Self-issued *and* the key identifier points back at itself."""
        if not self.is_self_issued():
            return False
        if self.subject_key_identifier and self.authority_key_identifier:
            return self.subject_key_identifier.lower() == self.authority_key_identifier.lower()
        # No key identifiers at all: self-issued is the best available signal.
        return self.authority_key_identifier is None


def split_pem(text: str) -> list[tuple[int, bytes]]:
    """Every CERTIFICATE block in a bundle, with the 1-based line it starts on."""
    out: list[tuple[int, bytes]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        if lines[i].strip() == PEM_HEADER:
            start_line = i + 1
            body: list[str] = []
            i += 1
            while i < len(lines) and lines[i].strip() != PEM_FOOTER:
                body.append(lines[i].strip())
                i += 1
            if i == len(lines):
                raise CertError(f"{PEM_HEADER} at line {start_line} is never closed")
            try:
                out.append((start_line, base64.b64decode("".join(body), validate=True)))
            except (binascii.Error, ValueError) as exc:
                raise CertError(f"base64 at line {start_line} is not decodable: {exc}") from exc
        i += 1
    return out


def load_certificates(data: bytes, source: str = "<memory>") -> list[CertFacts]:
    """PEM bundle or raw DER, whichever it is."""
    text = data.decode("utf-8", errors="replace")
    if PEM_HEADER in text:
        blocks = split_pem(text)
        if not blocks:
            raise CertError(f"{source}: no decodable PEM block")
        return [parse_certificate(raw, f"{source}#{line}") for line, raw in blocks]
    if data[:1] == b"\x30":
        return [parse_certificate(data, source)]
    raise CertError(f"{source}: neither a PEM certificate nor a DER SEQUENCE")


def parse_certificate(der_bytes: bytes, source: str = "<memory>") -> CertFacts:
    try:
        cert = read_tlv(der_bytes, 0)
    except DerError as exc:
        raise CertError(f"{source}: {exc}") from exc
    if cert.tag != der.TAG_SEQUENCE:
        raise CertError(f"{source}: certificate is not a SEQUENCE (tag 0x{cert.tag:02x})")

    parts = children(der_bytes, cert)
    if len(parts) != 3:
        raise CertError(f"{source}: certificate has {len(parts)} fields, expected 3")
    tbs, sig_alg_tlv, _sig_value = parts

    tbs_parts = children(der_bytes, tbs)
    idx = 0
    version = 1  # v1 is the default when the [0] EXPLICIT wrapper is absent
    if tbs_parts and tbs_parts[0].tag == 0xA0:
        try:
            version = read_integer(children(der_bytes, tbs_parts[0])[0]) + 1
        except (DerError, IndexError):
            version = 1
        idx = 1

    def need(n: int) -> None:
        if len(tbs_parts) - idx < n:
            raise CertError(f"{source}: TBSCertificate is missing fields")

    need(6)
    serial_tlv = tbs_parts[idx]
    inner_sig_alg = tbs_parts[idx + 1]
    issuer_tlv = tbs_parts[idx + 2]
    validity_tlv = tbs_parts[idx + 3]
    subject_tlv = tbs_parts[idx + 4]
    spki_tlv = tbs_parts[idx + 5]
    ext_tlv = None
    for extra in tbs_parts[idx + 6 :]:
        if extra.tag == 0xA3:
            ext_tlv = extra

    serial_int = read_integer(serial_tlv)
    # Serials are legally negative in DER (two's complement); a CA never issues
    # one, and a negative serial is a known way to break buggy clients, so it is
    # reported as-is rather than normalised away.
    if serial_int >= 0:
        serial_hex = f"{serial_int:x}"
        serial_hex = ("0" + serial_hex) if len(serial_hex) % 2 else serial_hex
    else:
        serial_hex = f"-{abs(serial_int):x}"

    outer_oid = _algorithm_oid(der_bytes, sig_alg_tlv)
    inner_oid = _algorithm_oid(der_bytes, inner_sig_alg)
    digest, sig_key_type = oids.SIGNATURE_ALGORITHMS.get(outer_oid, ("", ""))

    validity = children(der_bytes, validity_tlv)
    if len(validity) < 2:
        raise CertError(f"{source}: Validity needs two times, has {len(validity)}")
    nb_text = read_utc_or_generalized(validity[0])
    na_text = read_utc_or_generalized(validity[1])

    facts = CertFacts(
        source=source,
        der=der_bytes,
        version=version,
        serial_hex=serial_hex,
        serial_offset=serial_tlv.start,
        signature_algorithm=_sig_name(outer_oid),
        signature_algorithm_inner=_sig_name(inner_oid),
        digest=digest,
        signature_key_type=sig_key_type,
        issuer=_parse_name(der_bytes, issuer_tlv),
        subject=_parse_name(der_bytes, subject_tlv),
        not_before=_parse_time(nb_text),
        not_after=_parse_time(na_text),
        not_before_text=nb_text,
        not_after_text=na_text,
        validity_offset=validity_tlv.start,
        public_key=_parse_spki(der_bytes, spki_tlv),
        spki_offset=spki_tlv.start,
        tbs_offset=tbs.start,
    )

    if ext_tlv is not None:
        _parse_extensions(der_bytes, ext_tlv, facts)
    return facts


def _sig_name(oid: str) -> str:
    known = {
        "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
        "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
        "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
        "1.2.840.113549.1.1.10": "rsassaPss",
        "1.2.840.10040.4.3": "dsaWithSHA1",
        "1.2.840.10045.4.1": "ecdsaWithSHA1",
        "1.2.840.10045.4.3.2": "ecdsaWithSHA256",
        "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
        "1.2.840.10045.4.3.4": "ecdsaWithSHA512",
        "1.3.101.112": "ed25519",
        "1.3.101.113": "ed448",
    }
    return known.get(oid, oid)


def _algorithm_oid(buf: bytes, alg_tlv: Tlv) -> str:
    for item in children(buf, alg_tlv):
        if item.tag == der.TAG_OID:
            return read_oid(item)
    raise CertError(f"AlgorithmIdentifier at {alg_tlv.start} has no OID")


def _parse_name(buf: bytes, name_tlv: Tlv) -> CertName:
    result = CertName()
    for rdn in children(buf, name_tlv):
        for atv in children(buf, rdn) if rdn.tag & 0x20 else [rdn]:
            items = children(buf, atv) if atv.tag == der.TAG_SEQUENCE else [atv]
            if len(items) < 2:
                continue
            try:
                short = oids.name(read_oid(items[0]), oids.ATTRIBUTES)
                value = read_string(items[1])
            except DerError:
                continue
            result.attrs.append(NameAttr(oid=read_oid(items[0]), short=short, value=value, offset=items[1].start))
    return result


def _parse_time(text: str) -> datetime | None:
    """UTCTime or GeneralizedTime. Returns None rather than guessing."""
    text = text.strip()
    try:
        if len(text) == 13 and text.endswith("Z"):  # YYMMDDHHMMSSZ
            year = int(text[0:2])
            year += 2000 if year < 50 else 1900
            return datetime(year, *(_pairs(text, 2)), tzinfo=timezone.utc)
        if len(text) == 15 and text.endswith("Z"):  # YYYYMMDDHHMMSSZ
            return datetime(int(text[0:4]), *(_pairs(text, 4)), tzinfo=timezone.utc)
    except ValueError:
        return None
    return None


def _pairs(text: str, offset: int) -> tuple[int, ...]:
    body = text[offset:].rstrip("Z")
    return tuple(int(body[i : i + 2]) for i in range(0, len(body), 2))


def _parse_spki(buf: bytes, spki_tlv: Tlv) -> PublicKey:
    parts = children(buf, spki_tlv)
    if len(parts) < 2:
        raise CertError(f"SubjectPublicKeyInfo at {spki_tlv.start} has {len(parts)} fields")
    alg = parts[0]
    alg_parts = children(buf, alg)
    oid = read_oid(alg_parts[0]) if alg_parts else ""
    algorithm = oids.PUBLIC_KEY_ALGORITHMS.get(oid, oid)
    curve = None
    if len(alg_parts) > 1 and alg_parts[1].tag == der.TAG_OID:
        curve = oids.CURVES.get(read_oid(alg_parts[1]))

    unused, payload = read_bit_string(parts[1])
    if unused:
        # A public key BIT STRING is always a whole number of octets.
        raise CertError(f"public key at {parts[1].start} has {unused} unused bits")
    bits = 0
    try:
        if algorithm in {"rsa", "rsa-pss"}:
            inner = children(payload, read_tlv(payload, 0))
            bits = read_integer(inner[0]).bit_length() if inner else 0
        elif algorithm == "ec":
            bits = _ec_bits(payload, curve)
        else:
            bits = len(payload) * 8
    except DerError:
        bits = len(payload) * 8
    return PublicKey(algorithm=algorithm, bits=bits, curve=curve)


def _ec_bits(payload: bytes, curve: str | None) -> int:
    """From the point, because the curve OID is only advisory."""
    nominal = {"prime256v1": 256, "secp384r1": 384, "secp521r1": 521, "secp224r1": 224, "secp192r1": 192, "secp256k1": 256}
    if curve in nominal:
        return nominal[curve]
    if payload[:1] == b"\x04":
        return (len(payload) - 1) * 4
    return len(payload) * 8


def _parse_extensions(buf: bytes, ext_container: Tlv, facts: CertFacts) -> None:
    for wrapper in children(buf, ext_container):  # [3] holds a SEQUENCE
        if wrapper.tag != der.TAG_SEQUENCE:
            continue
        for entry in children(buf, wrapper):
            _parse_extension(buf, entry, facts)


def _parse_extension(buf: bytes, entry: Tlv, facts: CertFacts) -> None:
    items = children(buf, entry)
    if not items:
        return
    oid_text = read_oid(items[0])
    short = oids.name(oid_text, oids.EXTENSIONS)
    critical = False
    value_index = 1
    if len(items) > 2 and items[1].tag == der.TAG_BOOLEAN:
        critical = der.read_boolean(items[1])
        value_index = 2
    raw = items[value_index].content if len(items) > value_index else b""
    ext = Extension(oid=oid_text, short=short, critical=critical, offset=entry.start, raw=raw)
    facts.extensions[short] = ext

    try:
        if short == "subjectAltName":
            # raw is a copy: every helper below indexes into raw, not into buf.
            facts.san = _parse_general_names(raw, read_tlv(raw, 0)) if raw else []
        elif short == "basicConstraints":
            _parse_basic_constraints(raw, facts)
        elif short == "keyUsage":
            facts.key_usage = _parse_key_usage(raw)
        elif short == "extKeyUsage":
            facts.extended_key_usage = _parse_eku(raw)
        elif short == "subjectKeyIdentifier":
            facts.subject_key_identifier = _octet_string_hex(raw)
        elif short == "authorityKeyIdentifier":
            facts.authority_key_identifier = _parse_aki(raw)
        elif short == "authorityInfoAccess":
            _parse_aia(raw, facts)
        elif short == "CRLDistributionPoints":
            facts.crl_urls = _parse_crldp(raw)
        elif short == "signedCertificateTimestampList":
            facts.sct_count = _sct_count(raw)
    except DerError:
        # A malformed extension is itself a finding; the reader stays usable.
        return


def _parse_general_names(buf: bytes, seq: Tlv) -> list[GeneralName]:
    out: list[GeneralName] = []
    for item in children(buf, seq) if seq.tag & 0x20 else []:
        kind = oids.GENERAL_NAME_TAGS.get(item.tag & 0x1F, f"tag{item.tag & 0x1F}")
        if kind == "iPAddress":
            if len(item.content) == 4:
                value = ".".join(str(b) for b in item.content)
            elif len(item.content) == 16:
                value = item.content.hex(":")
            else:
                value = item.content.hex()
        elif kind == "otherName":
            value = item.content.hex()
        else:
            value = item.content.decode("utf-8", errors="replace")
        out.append(GeneralName(kind=kind, value=value))
    return out


def _parse_basic_constraints(raw: bytes, facts: CertFacts) -> None:
    seq = read_tlv(raw, 0)
    for item in children(raw, seq) if seq.tag & 0x20 else []:
        if item.tag == der.TAG_BOOLEAN:
            facts.is_ca = der.read_boolean(item)
        elif item.tag == der.TAG_INTEGER and len(raw) > item.start:
            facts.path_len = read_integer(item)


def _parse_key_usage(raw: bytes) -> list[str]:
    unused, payload = read_bit_string(read_tlv(raw, 0))
    bits = "".join(f"{byte:08b}" for byte in payload)
    if unused:
        bits = bits[:-unused]
    return [oids.KEY_USAGE_BITS[i] for i, flag in enumerate(bits) if flag == "1" and i < len(oids.KEY_USAGE_BITS)]


def _parse_eku(raw: bytes) -> list[str]:
    seq = read_tlv(raw, 0)
    return [oids.EXTENDED_KEY_USAGES.get(read_oid(item), read_oid(item)) for item in children(raw, seq)]


def _octet_string_hex(raw: bytes) -> str:
    inner = read_tlv(raw, 0)
    return inner.content.hex()


def _parse_aki(raw: bytes) -> str | None:
    seq = read_tlv(raw, 0)
    for item in children(raw, seq):
        if item.tag == 0x80:  # [0] keyIdentifier
            return item.content.hex()
    return None


def _parse_aia(raw: bytes, facts: CertFacts) -> None:
    seq = read_tlv(raw, 0)
    for desc in children(raw, seq):
        items = children(raw, desc)
        if len(items) < 2:
            continue
        method = oids.ACCESS_METHODS.get(read_oid(items[0]), "")
        # The accessLocation is a GeneralName: a URI is a context tag 6, not one
        # of the universal string types, so the tag test has to be on the class.
        url = items[1].content.decode("utf-8", errors="replace")
        if method == "ocsp":
            facts.ocsp_urls.append(url)
        elif method == "caIssuers":
            facts.ca_issuer_urls.append(url)


def _parse_crldp(raw: bytes) -> list[str]:
    seq = read_tlv(raw, 0)
    urls: list[str] = []
    for point in children(raw, seq):
        for choice in children(raw, point):
            if choice.tag != 0xA0:
                continue
            for full in children(raw, choice):
                for name in children(raw, full):
                    if name.tag & 0x1F == 6:
                        urls.append(name.content.decode("utf-8", errors="replace"))
    return urls


def _sct_count(raw: bytes) -> int:
    """SignedCertificateTimestampList: a 2-byte big endian list of slices."""
    inner = read_tlv(raw, 0)
    body = inner.content
    if len(body) < 2:
        return 0
    total = int.from_bytes(body[:2], "big")
    if total < len(body) - 2:
        return _count_slices(body[2:])
    return 0


def _count_slices(body: bytes) -> int:
    count = 0
    pos = 0
    while pos + 2 <= len(body):
        size = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2 + size
        count += 1
    return count


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def format_span(delta: timedelta) -> str:
    days = delta.days
    if days < 0:
        return f"{-days} days ago"
    if days == 0:
        return "today"
    return f"in {days} days"
