"""Everything that touches the network.

The standard library's ``ssl`` module does the handshake; the work here is
asking the same question in enough different ways to be able to answer it. A
protocol version is probed by pinning one version and seeing whether the server
follows; a cipher is probed by offering exactly one and seeing whether it is
taken.

No result here is inferred from a banner, and a handshake that fails is a
result, not an error: the rules need to know what was refused as much as what
was accepted.
"""

from __future__ import annotations

import concurrent.futures
import socket
import ssl
from dataclasses import dataclass

from .model import (
    CipherOffer,
    Cookie,
    HttpProbe,
    HttpResponse,
    ProbeResult,
    ProtocolOffer,
)
from .x509 import CertError, parse_certificate

# The versions worth asking about, oldest first. SSLv3 is probed only when the
# OpenSSL build still allows it to be named: on a modern build the answer is
# "not offered" and saying "could not test" would be more honest than guessing.
VERSION_ORDER = [
    ("SSLv3", "SSLv3"),
    ("TLSv1.0", "TLSv1"),
    ("TLSv1.1", "TLSv1_1"),
    ("TLSv1.2", "TLSv1_2"),
    ("TLSv1.3", "TLSv1_3"),
]

TLS13_SUITES = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
]

# A name fragment is enough to classify a suite; the tables behind openssl's
# names are far larger than the set a server actually negotiates.
AEAD_MARKERS = ("GCM", "POLY1305", "CHACHA20", "CCM")
CBC_MARKERS = ("CBC",)
WEAK_MARKERS = ("RC4", "DES-CBC3", "3DES", "NULL", "EXPORT", "MD5", "IDEA", "SEED", "PSK", "aNULL", "eNULL", "LOW")
STREAM_MARKERS = ("RC4", "CHACHA20")
BLOCK_CIPHERS = ("AES", "CAMELLIA", "DES", "SEED", "IDEA", "ARIA")
FORWARD_SECRET_MARKERS = ("ECDHE", "DHE", "ECDH_", "TLS_AES", "TLS_CHACHA20")
STATIC_MARKERS = ("TLS_RSA_", "RSA_WITH", "TLS_DH_", "TLS_ECDH_")

DEFAULT_TIMEOUT = 6.0
DEFAULT_PORT = 443

# A server old enough to still speak TLS 1.0 usually also insists on a cipher
# the modern default list has dropped (SHA1 MAC, static RSA key exchange). The
# first probe uses the default list; only if that is refused outright does the
# scanner lower the security level and try again, and it says so in the note.
LEGACY_CIPHERS = "ALL:@SECLEVEL=0"
_NO_CIPHER_MARKERS = (
    "no ciphers available",
    "no cipher match",
    "no cipher overlap",
    "handshake failure",
    "unsafe legacy",
    "unsupported protocol",
)

# Suites a modern default list has dropped, kept here so a scanner can still
# name them when a server offers them.
LEGACY_CANDIDATES = (
    "AES128-SHA",
    "AES256-SHA",
    "DES-CBC3-SHA",
    "ECDHE-RSA-DES-CBC3-SHA",
    "DHE-RSA-AES128-SHA",
    "DHE-RSA-AES256-SHA",
    "DHE-RSA-DES-CBC3-SHA",
    "ECDHE-RSA-RC4-SHA",
    "RC4-SHA",
    "RC4-MD5",
    "NULL-SHA",
    "NULL-MD5",
    "EXP-RC4-MD5",
    "EXP-DES-CBC-SHA",
    "IDEA-CBC-SHA",
    "SEED-SHA",
    "CAMELLIA128-SHA",
    "AES128-SHA256",
    "AES256-SHA256",
)


def _needs_legacy_ciphers(error: str) -> bool:
    lowered = error.lower()
    return any(marker in lowered for marker in _NO_CIPHER_MARKERS)


class ProbeError(RuntimeError):
    """The target could not be reached at all."""


@dataclass
class _Handshake:
    ok: bool
    version: str | None = None
    cipher: str | None = None
    bits: int | None = None
    error: str = ""


def _context(
    minimum: ssl.TLSVersion | None = None,
    maximum: ssl.TLSVersion | None = None,
    ciphers: str | None = None,
    verify: bool = False,
    server_hostname: str | None = None,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Verification is off by default: the audit is about what the server offers,
    # and a bad certificate is reported by the rules with more detail than an
    # SSLCertVerificationError would carry.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
    if verify:
        ctx.load_default_certs()
    if minimum is not None:
        ctx.minimum_version = minimum
    if maximum is not None:
        ctx.maximum_version = maximum
    if ciphers:
        ctx.set_ciphers(ciphers)
    return ctx


def _version_constant(name: str) -> ssl.TLSVersion | None:
    return getattr(ssl.TLSVersion, name, None)


def handshake(
    host: str,
    port: int,
    server_hostname: str | None = None,
    minimum: ssl.TLSVersion | None = None,
    maximum: ssl.TLSVersion | None = None,
    ciphers: str | None = None,
    verify: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    allow_legacy_retry: bool = True,
) -> _Handshake:
    """One connection. Failure is returned, not raised.

    ``allow_legacy_retry`` is off when the caller is asking about one specific
    suite: falling back to "anything at SECLEVEL=0" would answer a different
    question than the one that was asked.
    """
    sni = server_hostname or host

    def attempt(cipher_list: str | None) -> _Handshake:
        try:
            ctx = _context(minimum, maximum, cipher_list, verify, sni)
        except ssl.SSLError as exc:
            return _Handshake(ok=False, error=f"context: {exc}")
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(
                raw, server_hostname=sni
            ) as tls:
                cipher = tls.cipher()
                return _Handshake(
                    ok=True,
                    version=tls.version(),
                    cipher=cipher[0] if cipher else None,
                    bits=cipher[2] if cipher else None,
                    error="with a lowered security level" if cipher_list == LEGACY_CIPHERS else "",
                )
        except ssl.SSLError as exc:
            return _Handshake(ok=False, error=str(exc) or exc.__class__.__name__)
        except (TimeoutError, OSError) as exc:
            return _Handshake(ok=False, error=f"{exc.__class__.__name__}: {exc}")

    first = attempt(ciphers)
    if first.ok or not allow_legacy_retry or not _needs_legacy_ciphers(first.error):
        return first
    second = attempt(LEGACY_CIPHERS)
    if second.ok:
        return second
    return first


def probe_protocols(
    host: str,
    port: int,
    sni: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[list[ProtocolOffer], list[str]]:
    offers: list[ProtocolOffer] = []
    errors: list[str] = []
    for label, attr in VERSION_ORDER:
        version = _version_constant(attr)
        if version is None:
            # Not nameable on this OpenSSL build, so it cannot be negotiated.
            offers.append(ProtocolOffer(version=label, offered=False, note="not supported by this OpenSSL build"))
            continue
        result = handshake(host, port, sni, minimum=version, maximum=version, timeout=timeout)
        if result.ok:
            note = result.cipher or ""
            if result.error:
                note = f"{note} ({result.error})"
            offers.append(ProtocolOffer(version=label, offered=True, note=note))
        else:
            lowered = result.error.lower()
            refused = "no protocols available" in lowered or "alert protocol" in lowered or "handshake" in lowered
            offers.append(
                ProtocolOffer(
                    version=label,
                    offered=False,
                    note="" if refused else result.error[:120],
                )
            )
    return offers, errors


def _classify(name: str) -> tuple[bool, bool, str, str]:
    """(forward_secret, aead, mode, mac) for an OpenSSL cipher name."""
    upper = name.upper()
    aead = any(marker in upper for marker in AEAD_MARKERS) and "CBC" not in upper
    if aead:
        mode = "aead"
    elif any(marker in upper for marker in STREAM_MARKERS):
        mode = "stream"
    elif any(marker in upper for marker in CBC_MARKERS) or any(marker in upper for marker in BLOCK_CIPHERS):
        # OpenSSL leaves "CBC" out of the older names, so AES128-SHA is a CBC
        # suite that does not say so.
        mode = "cbc"
    else:
        mode = "unknown"
    forward_secret = any(marker in upper for marker in FORWARD_SECRET_MARKERS) and not any(
        marker in upper for marker in ("TLS_RSA_", "RSA_WITH")
    )
    if "SHA384" in upper:
        mac = "sha384"
    elif "SHA256" in upper:
        mac = "sha256"
    elif "MD5" in upper:
        mac = "md5"
    elif "SHA" in upper:
        mac = "sha1"
    else:
        mac = ""
    return forward_secret, aead, mode, mac


def candidate_ciphers() -> list[str]:
    """Every suite name this OpenSSL build can be asked to offer."""
    try:
        ctx = _context()
        return [entry["name"] for entry in ctx.get_ciphers()]
    except ssl.SSLError:
        return []


def _tls12_candidates(names: list[str]) -> list[str]:
    return [n for n in names if not n.startswith("TLS_")]


def probe_ciphers(
    host: str,
    port: int,
    sni: str,
    names: list[str] | None = None,
    workers: int = 8,
    timeout: float = DEFAULT_TIMEOUT,
    limit: int = 0,
    legacy: bool = True,
) -> list[CipherOffer]:
    """Offer one suite at a time and record which ones the server takes.

    Cost: one handshake per candidate, which is why it is the only step with a
    worker pool and a ``limit``. ``limit=0`` means every candidate. With
    ``legacy`` the candidates a modern default list has dropped are asked about
    too, at a lowered security level, because that is the only way to find out
    whether a server still takes RC4.
    """
    names = list(names) if names is not None else _tls12_candidates(candidate_ciphers())
    if legacy:
        names += [n for n in LEGACY_CANDIDATES if n not in names]
    if limit and len(names) > limit:
        names = names[:limit]

    tls12 = _version_constant("TLSv1_2")

    def one(name: str) -> CipherOffer | None:
        result = handshake(
            host, port, sni, minimum=tls12, maximum=tls12, ciphers=name, timeout=timeout, allow_legacy_retry=False
        )
        if not result.ok and _needs_legacy_ciphers(result.error):
            result = handshake(
                host,
                port,
                sni,
                minimum=tls12,
                maximum=tls12,
                ciphers=f"{name}:@SECLEVEL=0",
                timeout=timeout,
                allow_legacy_retry=False,
            )
        if not result.ok or not result.cipher:
            return None
        forward_secret, aead, mode, mac = _classify(result.cipher)
        return CipherOffer(
            name=result.cipher,
            protocol=result.version or "TLSv1.2",
            bits=result.bits or 0,
            forward_secret=forward_secret,
            aead=aead,
            mode=mode,
            mac=mac,
        )

    out: list[CipherOffer] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for offer in pool.map(one, names):
            if offer is not None:
                out.append(offer)
    return _dedupe(out)


def probe_tls13_suites(
    host: str,
    port: int,
    sni: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[CipherOffer]:
    version = _version_constant("TLSv1_3")
    out: list[CipherOffer] = []
    if version is None:
        return out
    for name in TLS13_SUITES:
        result = handshake(host, port, sni, minimum=version, maximum=version, ciphers=name, timeout=timeout)
        if result.ok and result.cipher:
            _forward_secret, aead, mode, mac = _classify(result.cipher)
            out.append(
                CipherOffer(
                    name=result.cipher,
                    protocol=result.version or "TLSv1.3",
                    bits=result.bits or 0,
                    forward_secret=True,
                    aead=aead,
                    mode=mode,
                    mac=mac,
                )
            )
    return _dedupe(out)


def _dedupe(offers: list[CipherOffer]) -> list[CipherOffer]:
    seen: dict[str, CipherOffer] = {}
    for offer in offers:
        seen.setdefault(offer.name, offer)
    return list(seen.values())


def read_chain(
    host: str,
    port: int,
    sni: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[list[bytes], str, str | None]:
    """(leaf + intermediates as DER, chain kind, error text)."""
    # The chain is read with the default cipher list first and with a lowered
    # security level second: a server that only speaks AES128-SHA refuses the
    # modern default outright, and returning no chain for it would hide the
    # certificate rules behind a cipher negotiation detail.
    error: str | None = None
    for cipher_list in (None, LEGACY_CIPHERS):
        ders, kind, error = _read_chain_once(host, port, sni, timeout, cipher_list)
        if ders or cipher_list == LEGACY_CIPHERS:
            return ders, kind, error
    return [], "unreachable", error


def _read_chain_once(
    host: str,
    port: int,
    sni: str,
    timeout: float,
    ciphers: str | None,
) -> tuple[list[bytes], str, str | None]:
    ctx = _context(verify=False, ciphers=ciphers)
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(
            raw, server_hostname=sni
        ) as tls:
            ders: list[bytes] = []
            # get_unverified_chain is 3.13+; before that the leaf is all the
            # standard library exposes, which is why the chain rules treat a
            # one-element chain as "unknown" rather than "incomplete".
            getter = getattr(tls, "get_unverified_chain", None)
            if getter is not None:
                try:
                    presented = getter()
                except (ssl.SSLError, ValueError, OSError):
                    presented = []
                for cert in presented:
                    encoded = _cert_der(cert)
                    if encoded:
                        ders.append(encoded)
                if not ders:
                    ders = [tls.getpeercert(binary_form=True) or b""]
            else:
                ders = [tls.getpeercert(binary_form=True) or b""]
            return [d for d in ders if d], "unverified", None
    except ssl.SSLError as exc:
        return [], "untrusted", str(exc)
    except (TimeoutError, OSError) as exc:
        return [], "unreachable", f"{exc.__class__.__name__}: {exc}"


def _cert_der(cert: object) -> bytes:
    """DER out of whatever this build hands back for a chain element.

    3.13 returns ssl.SSLCertificate, whose public_bytes() is DER; a build that
    exposes something else is skipped rather than crashing the scan.
    """
    for attr in ("public_bytes", "to_cryptography"):
        fn = getattr(cert, attr, None)
        if fn is None:
            continue
        try:
            data = fn()
        except (TypeError, ValueError, OSError):
            continue
        if isinstance(data, bytes):
            return data
        inner = getattr(data, "public_bytes", None)
        if inner is not None:
            try:
                return inner()
            except (TypeError, ValueError):  # pragma: no cover - build dependent
                return b""
    return b""


def verify_chain(
    host: str,
    port: int,
    sni: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[str, str | None]:
    """Does it validate against the system trust store?"""
    result = handshake(host, port, sni, verify=True, timeout=timeout)
    if result.ok:
        return "trusted", None
    error = result.error
    lowered = error.lower()
    # OpenSSL writes "self-signed" with the hyphen and "unable to get local
    # issuer certificate" without one; both mean the chain the server sent ends
    # before it reaches anything the client trusts.
    if "unable to get local issuer certificate" in lowered or "self signed" in lowered or "self-signed" in lowered:
        return "incomplete", error
    if "certificate verify failed" in error:
        return "untrusted", error
    return "unknown", error or "handshake failed"


def _request(host: str, port: int, tls: bool, path: str = "/", timeout: float = DEFAULT_TIMEOUT) -> HttpResponse | None:
    """A minimal HTTP/1.1 GET. Enough to read headers, no more."""
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: tlslint\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    )
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            if tls:
                ctx = _context()
                with ctx.wrap_socket(raw, server_hostname=host) as sock:
                    sock.sendall(request.encode("ascii"))
                    payload = _read_all(sock)
            else:
                raw.sendall(request.encode("ascii"))
                payload = _read_all(raw)
    except (TimeoutError, OSError, ssl.SSLError):
        return None
    return _parse_response(payload)


def _read_all(sock: socket.socket, cap: int = 65536) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < cap:
        try:
            chunk = sock.recv(4096)
        except (TimeoutError, OSError):
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _parse_response(payload: bytes) -> HttpResponse | None:
    if not payload:
        return None
    head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    lines = head.split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        return None
    try:
        status = int(lines[0].split(" ")[1])
    except (IndexError, ValueError):
        return None
    headers: dict[str, str] = {}
    cookies: list[Cookie] = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()
        if key.strip().lower() == "set-cookie":
            cookies.append(_parse_cookie(value.strip()))
    return HttpResponse(status=status, headers=headers, cookies=cookies)


def _parse_cookie(value: str) -> Cookie:
    parts = [p.strip() for p in value.split(";")]
    name = parts[0].split("=", 1)[0] if parts else ""
    lowered = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else "") for p in parts[1:]}
    return Cookie(
        name=name,
        secure="secure" in lowered,
        httponly="httponly" in lowered,
        samesite=lowered.get("samesite") or None,
    )


def probe_http(host: str, port: int, plain_port: int = 80, timeout: float = DEFAULT_TIMEOUT) -> HttpProbe:
    """HSTS, cookies, and what plain HTTP does with a visitor."""
    probe = HttpProbe()
    https = _request(host, port if port != plain_port else 443, tls=True, timeout=timeout)
    probe.https = https
    try:
        plain = _request(host, plain_port, tls=False, timeout=timeout)
    except OSError:
        plain = None
    probe.http = plain
    if plain is not None:
        location = plain.headers.get("location")
        probe.http_location = location
        if location:
            probe.redirect_chain.append(location)
    return probe


def probe(
    host: str,
    port: int = DEFAULT_PORT,
    sni: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    deep: bool = True,
    cipher_limit: int = 0,
    workers: int = 8,
    with_http: bool = True,
    plain_port: int = 80,
) -> ProbeResult:
    """The whole conversation with a server."""
    server_hostname = sni or host
    result = ProbeResult(host=host, port=port, sni=server_hostname)

    offers, errors = probe_protocols(host, port, server_hostname, timeout=timeout)
    result.protocols = offers
    result.errors.extend(errors)
    if not any(o.offered for o in offers):
        result.errors.append("no protocol version could be negotiated")

    preferred = handshake(host, port, server_hostname, timeout=timeout)
    if preferred.ok:
        result.negotiated_protocol = preferred.version
        result.negotiated_cipher = preferred.cipher
        result.negotiated_bits = preferred.bits

    if deep:
        result.offers = probe_ciphers(host, port, server_hostname, workers=workers, timeout=timeout, limit=cipher_limit)
        result.offers += probe_tls13_suites(host, port, server_hostname, timeout=timeout)

    ders, kind, error = read_chain(host, port, server_hostname, timeout=timeout)
    result.chain_kind = kind
    result.chain_error = error
    for index, raw in enumerate(ders):
        try:
            result.chain.append(parse_certificate(raw, source=f"peer[{index}]"))
        except CertError as exc:
            result.errors.append(str(exc))

    verified, verification_error = verify_chain(host, port, server_hostname, timeout=timeout)
    if verified == "trusted":
        result.chain_kind = "trusted"
    elif verified == "incomplete" and kind == "unverified":
        result.chain_kind = "incomplete"
        result.chain_error = verification_error

    if with_http:
        result.http = probe_http(host, port, plain_port=plain_port, timeout=timeout)
    return result


def split_host(value: str) -> tuple[str, int]:
    """``example.com``, ``example.com:8443`` or ``[::1]:8443``."""
    if value.startswith("["):
        end = value.find("]")
        if end != -1:
            host = value[1:end]
            rest = value[end + 1 :]
            if rest.startswith(":"):
                return host, int(rest[1:])
            return host, DEFAULT_PORT
    if ":" in value and not value.endswith(":"):
        host, _, port_text = value.rpartition(":")
        if port_text.isdigit():
            return host, int(port_text)
    return value, DEFAULT_PORT
