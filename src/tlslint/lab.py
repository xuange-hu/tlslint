"""A TLS server you run on purpose, so the scanner has something to talk to.

Everything else in this project needs a target. ``tlslint lab`` starts one on
localhost with the bundled self-signed certificate, which means the demo, the
tests and the CI jobs can exercise real handshakes without touching the
network, and without depending on somebody else's server still being
configured the way it was when the test was written.

Profiles pick the personality:

    modern   TLS 1.3 and 1.2, AEAD only
    weak     modern protocols, but a short HSTS and unflagged cookies
    legacy   TLS 1.0 and 1.1 only, CBC, 128-bit, no HSTS
    broken   whatever the local OpenSSL will still enable at SECLEVEL=0
"""

from __future__ import annotations

import contextlib
import http.server
import ssl
import threading
from dataclasses import dataclass, field
from pathlib import Path

DATA = Path(__file__).parent / "data"
LAB_CERT = DATA / "lab.pem"
LAB_KEY = DATA / "lab.key"

PROFILES = ("modern", "weak", "legacy", "tls13", "aes128", "mismatched", "custom")


@dataclass
class LabConfig:
    profile: str = "modern"
    host: str = "127.0.0.1"
    https_port: int = 0  # 0 means "any free port"
    http_port: int = 0
    certfile: str = str(LAB_CERT)
    keyfile: str = str(LAB_KEY)
    hsts: str | None = "max-age=31536000; includeSubDomains; preload"
    cookie: str = "session=lab; Path=/; Secure; HttpOnly; SameSite=Lax"
    http_redirect: str | None = None  # None sends 200 instead of a redirect
    https_redirect: str | None = None
    protocols: tuple[str, str] = ("TLSv1_2", "TLSv1_3")
    ciphers: str | None = None

    def __post_init__(self) -> None:
        # "custom" keeps whatever the caller set: the demo and the tests use it
        # to build a server that is wrong in exactly one way.
        if self.profile == "modern":
            self.hsts = "max-age=31536000; includeSubDomains; preload"
            self.cookie = "session=lab; Path=/; Secure; HttpOnly; SameSite=Lax"
            self.http_redirect = "https://{host}:{https_port}/"
            self.protocols = ("TLSv1_2", "TLSv1_3")
        elif self.profile == "weak":
            # A short max-age with neither includeSubDomains nor preload, and a
            # cookie with none of the three attributes.
            self.hsts = "max-age=300"
            self.cookie = "session=lab; Path=/"
            self.http_redirect = "http://{host}:{http_port}/second"
            self.protocols = ("TLSv1_2", "TLSv1_3")
        elif self.profile == "legacy":
            # TLS 1.0 upward, with the security level lowered so the old suites
            # are offered at all. SECLEVEL=0 is a switch for a lab server, never
            # a suggestion for anything else. TLS 1.1 is *not* set as the
            # maximum here: OpenSSL 3 answers an internal error when it is, so
            # the profile goes up to 1.2 and lets 1.0 and 1.1 be reached.
            self.hsts = None
            self.cookie = "session=lab; Path=/"
            self.http_redirect = None
            self.protocols = ("TLSv1", "TLSv1_2")
            self.ciphers = "ALL:@SECLEVEL=0"
        elif self.profile == "tls13":
            # TLS 1.3 and nothing else: a configuration that strands every
            # client that can only reach 1.2.
            self.hsts = None
            self.cookie = "session=lab; Path=/"
            self.http_redirect = None
            self.protocols = ("TLSv1_3", "TLSv1_3")
        elif self.profile == "aes128":
            # One 128-bit CBC suite with static RSA key transport.
            self.hsts = None
            self.cookie = "session=lab; Path=/"
            self.http_redirect = None
            self.protocols = ("TLSv1_2", "TLSv1_2")
            self.ciphers = "AES128-SHA:@SECLEVEL=0"
        elif self.profile == "mismatched":
            # Two certificates that have nothing to do with each other, sent as
            # one chain: the leaf's issuer is not the second certificate's
            # subject, which is the mistake that is easiest to ship.
            self.hsts = None
            self.cookie = "session=lab; Path=/; Secure; HttpOnly; SameSite=Lax"
            self.http_redirect = "https://{host}:{https_port}/"
            self.protocols = ("TLSv1_2", "TLSv1_3")
            self.certfile = str(DATA / "mismatched.pem")


def _handler(
    config: LabConfig,
    ports: dict[str, int],
    tls: bool,
) -> type[http.server.BaseHTTPRequestHandler]:
    # ports is a dict rather than two numbers because neither port is known
    # until the socket is bound, which happens after the handler class exists.
    hsts = config.hsts
    cookie = config.cookie
    redirect = config.https_redirect if tls else config.http_redirect

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "tlslintlab"
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args) -> None:
            return

        def do_GET(self) -> None:
            if redirect is not None:
                target = redirect.format(
                    host=config.host, https_port=ports.get("https", 0), http_port=ports.get("http", 0), path=self.path
                )
                self.send_response(302)
                self.send_header("Location", target)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"tlslint lab\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            if hsts:
                self.send_header("Strict-Transport-Security", hsts)
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(body)

        do_HEAD = do_GET

    return Handler


def _server_context(config: LabConfig) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=config.certfile, keyfile=config.keyfile)
    minimum, maximum = config.protocols
    ctx.minimum_version = getattr(ssl.TLSVersion, minimum)
    ctx.maximum_version = getattr(ssl.TLSVersion, maximum)
    if config.ciphers:
        with contextlib.suppress(ssl.SSLError):
            ctx.set_ciphers(config.ciphers)
            # An OpenSSL build that will not re-enable RC4 is not a failure of
            # the lab: the profile simply offers what it can.
            pass
    return ctx


@dataclass
class Lab:
    """A running pair of servers and the ports they ended up on."""

    config: LabConfig
    https_port: int = 0
    http_port: int = 0
    _https: http.server.ThreadingHTTPServer | None = field(default=None, repr=False)
    _http: http.server.ThreadingHTTPServer | None = field(default=None, repr=False)
    _threads: list[threading.Thread] = field(default_factory=list, repr=False)

    @property
    def target(self) -> str:
        return f"{self.config.host}:{self.https_port}"

    def start(self) -> Lab:
        ports: dict[str, int] = {"https": self.https_port, "http": self.http_port}
        handler = _handler(self.config, ports, tls=True)
        self._https = http.server.ThreadingHTTPServer((self.config.host, self.https_port), handler)
        self.https_port = self._https.server_address[1]
        ports["https"] = self.https_port
        ctx = _server_context(self.config)
        self._https.socket = ctx.wrap_socket(self._https.socket, server_side=True)

        # The plain HTTP half exists so the redirect rules have something to
        # read: it is the server a visitor reaches before HSTS applies.
        self._http = http.server.ThreadingHTTPServer(
            (self.config.host, self.http_port), _handler(self.config, ports, tls=False)
        )
        self.http_port = self._http.server_address[1]
        ports["http"] = self.http_port

        for server in (self._https, self._http):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self._threads.append(thread)
        return self

    def stop(self) -> None:
        for server in (self._https, self._http):
            if server is not None:
                server.shutdown()
                server.server_close()
        for thread in self._threads:
            thread.join(timeout=2)

    def __enter__(self) -> Lab:
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()


def start(config: LabConfig | None = None, **kwargs) -> Lab:
    return Lab(config=config or LabConfig(**kwargs)).start()
