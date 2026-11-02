"""Command line entry point.

    tlslint scan example.com
    tlslint scan example.com:8443 --json
    tlslint cert cert.pem chain.pem
    tlslint cert leaf.pem --hostname example.com
    tlslint rules --category certificate
    tlslint lab --profile weak
    tlslint demo
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from . import demo as demo_mod
from . import lab as lab_mod
from .analyze import audit_files, audit_probe
from .model import SEVERITIES, rank
from .probe import DEFAULT_PORT, probe, split_host
from .render import render_json, render_report, render_rules
from .rules import CATEGORIES, RULES, rules_for
from .sarif import dumps as sarif_dumps
from .x509 import CertError, load_certificates

EXIT_CLEAN = 0
EXIT_FOUND = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tlslint",
        description="Audit a TLS server or a certificate, with the bytes that prove each finding.",
    )
    parser.add_argument("--version", action="version", version=f"tlslint {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="talk to a server and read what it offers")
    scan.add_argument("target", help="host, host:port, or [ipv6]:port")
    scan.add_argument("--sni", help="name to send in SNI (defaults to the host)")
    scan.add_argument("--timeout", type=float, default=6.0)
    scan.add_argument("--workers", type=int, default=8, help="parallel handshakes during suite enumeration")
    scan.add_argument("--cipher-limit", type=int, default=0, help="stop after N candidate suites (0 = all)")
    scan.add_argument("--quick", action="store_true", help="versions and certificate only, no suite enumeration")
    scan.add_argument("--no-http", action="store_true", help="skip the HTTP header and redirect checks")
    scan.add_argument("--plain-port", type=int, default=80, help="port to send the plain HTTP request to")
    scan.add_argument("--json", action="store_true")
    scan.add_argument("--sarif", metavar="PATH", help="also write a SARIF 2.1.0 report")
    scan.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 when a finding at this level or worse exists")
    _add_output(scan)

    cert = sub.add_parser("cert", help="read certificates from disk, no connection")
    cert.add_argument("paths", nargs="+", help="PEM, PEM bundle or DER files")
    cert.add_argument("--hostname", help="name the certificate is expected to cover")
    cert.add_argument("--now", help="judge validity against this ISO-8601 instant instead of now")
    cert.add_argument("--json", action="store_true")
    cert.add_argument("--sarif", metavar="PATH")
    cert.add_argument("--fail-on", choices=SEVERITIES)

    rules = sub.add_parser("rules", help="list the rules")
    rules.add_argument("--category", choices=sorted(CATEGORIES))
    rules.add_argument("--severity", choices=SEVERITIES)

    lab = sub.add_parser("lab", help="start a local TLS server to scan")
    lab.add_argument("--profile", choices=list(lab_mod.PROFILES), default="modern")
    lab.add_argument("--host", default="127.0.0.1")
    lab.add_argument("--https-port", type=int, default=0)
    lab.add_argument("--http-port", type=int, default=0)

    dem = sub.add_parser("demo", help="scan local servers and fixtures, no network access")
    dem.add_argument("--json", action="store_true")
    dem.add_argument("--sarif", metavar="PATH")
    dem.add_argument("--timeout", type=float, default=6.0)
    return parser


def _add_output(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--quiet", action="store_true", help="print the grade and the finding count only")


def _emit(report, as_json: bool, quiet: bool, sarif_path: str | None) -> None:
    if as_json:
        print(render_json(report))
    elif quiet:
        counts = report.by_severity()
        print(f"{report.target}: grade {report.grade}, {len(report.findings)} finding(s) {counts}")
    else:
        print(render_report(report))
    if sarif_path:
        # encoding is explicit: rule text is UTF-8 and the Windows default is cp1252
        Path(sarif_path).write_text(sarif_dumps(report) + "\n", encoding="utf-8")


def _exit_code(report, fail_on: str | None) -> int:
    if fail_on is None:
        return EXIT_CLEAN
    if report.worst() is not None and rank(report.worst()) <= rank(fail_on):
        return EXIT_FOUND
    return EXIT_CLEAN


def cmd_scan(args: argparse.Namespace) -> int:
    host, port = split_host(args.target)
    if port == 0:
        port = DEFAULT_PORT
    result = probe(
        host,
        port,
        sni=args.sni,
        timeout=args.timeout,
        deep=not args.quick,
        cipher_limit=args.cipher_limit,
        workers=args.workers,
        with_http=not args.no_http,
        plain_port=args.plain_port,
    )
    report = audit_probe(result)
    _emit(report, args.json, args.quiet, args.sarif)
    return _exit_code(report, args.fail_on)


def cmd_cert(args: argparse.Namespace) -> int:
    now = datetime.now(timezone.utc)
    if args.now:
        now = datetime.fromisoformat(args.now)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
    pairs: list[tuple[str, object]] = []
    errors: list[str] = []
    for path in args.paths:
        target = Path(path)
        if not target.is_file():
            errors.append(f"{path}: no such file")
            continue
        try:
            for cert in load_certificates(target.read_bytes(), source=str(target)):
                pairs.append((str(target), cert))
        except CertError as exc:
            errors.append(str(exc))
    if not pairs:
        for error in errors:
            print(error, file=sys.stderr)
        return EXIT_USAGE

    hostnames = {source: args.hostname for source, _ in pairs} if args.hostname else {}
    report = audit_files(pairs, hostnames=hostnames, now=now)
    report.notes.extend(errors)
    _emit(report, args.json, False, args.sarif)
    return _exit_code(report, args.fail_on)


def cmd_rules(args: argparse.Namespace) -> int:
    selected = rules_for(args.category, args.severity)
    print(f"{len(selected)} of {len(RULES)} rules")
    print()
    print(render_rules(selected))
    return EXIT_CLEAN


def cmd_lab(args: argparse.Namespace) -> int:
    config = lab_mod.LabConfig(profile=args.profile, host=args.host, https_port=args.https_port, http_port=args.http_port)
    server = lab_mod.Lab(config=config).start()
    print(f"https://{server.target}  (profile {args.profile})")
    print(f"http://{server.config.host}:{server.http_port}")
    print("Ctrl-C to stop")
    try:
        import time

        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop()
        print("stopped")
    return EXIT_CLEAN


def cmd_demo(args: argparse.Namespace) -> int:
    result = demo_mod.run(timeout=args.timeout)
    report = demo_mod.as_report(result)
    _emit(report, args.json, False, args.sarif)
    return EXIT_CLEAN


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "scan": cmd_scan,
        "cert": cmd_cert,
        "rules": cmd_rules,
        "lab": cmd_lab,
        "demo": cmd_demo,
    }
    return handlers[args.command](args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
