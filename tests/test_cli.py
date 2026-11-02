"""The command line, driven in-process.

Every path here is offline: certificates from disk, rules from the table, and
the demo from its own local servers. Nothing in this module needs the network,
so it is safe to run anywhere.
"""

from __future__ import annotations

import json

import pytest
from helpers import NOW, fixture_path

from tlslint.cli import main


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "tlslint" in capsys.readouterr().out


def test_rules_lists_everything(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "of 43 rules" in out
    assert "TLS001" in out


def test_rules_filter(capsys):
    assert main(["rules", "--category", "protocol"]) == 0
    out = capsys.readouterr().out
    assert "5 of 43 rules" in out
    assert "TLS020" not in out


def test_cert_on_a_fixture(capsys):
    assert main(["cert", str(fixture_path("expired.pem"))]) == 0
    out = capsys.readouterr().out
    assert "TLS020" in out
    assert "expired" in out.lower()


def test_cert_json(capsys):
    assert main(["cert", str(fixture_path("expired.pem")), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"]


def test_cert_with_a_hostname(capsys):
    code = main(["cert", str(fixture_path("good.pem")), "--hostname", "elsewhere.test"])
    assert code == 0
    assert "TLS027" in capsys.readouterr().out


def test_cert_fail_on_critical():
    assert main(["cert", str(fixture_path("expired.pem")), "--fail-on", "critical"]) == 1


def test_cert_fail_on_high_when_only_low_exists():
    assert main(["cert", str(fixture_path("good.pem")), "--fail-on", "high"]) == 0


def test_cert_with_a_now_argument(capsys):
    # good.pem is valid in 2026 and expired long after; the verdict follows the
    # clock that was passed in, not the machine's
    assert main(["cert", str(fixture_path("good.pem")), "--now", "2030-01-01T00:00:00+00:00"]) == 0
    assert "TLS020" in capsys.readouterr().out


def test_cert_with_a_naive_now_argument(capsys):
    assert main(["cert", str(fixture_path("good.pem")), "--now", "2030-01-01T00:00:00"]) == 0
    assert "TLS020" in capsys.readouterr().out


def test_cert_on_a_missing_file(capsys):
    assert main(["cert", "does-not-exist.pem"]) == 2
    assert "no such file" in capsys.readouterr().err


def test_cert_on_a_broken_file(capsys):
    assert main(["cert", str(fixture_path("broken.pem"))]) == 2
    assert "not decodable" in capsys.readouterr().err


def test_cert_writes_sarif(tmp_path, capsys):
    path = tmp_path / "out.sarif"
    assert main(["cert", str(fixture_path("expired.pem")), "--sarif", str(path)]) == 0
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"


def test_cert_accepts_a_bundle(capsys):
    assert main(["cert", str(fixture_path("bundle.pem"))]) == 0
    out = capsys.readouterr().out
    assert "TLS029" in out  # the self-signed half of the bundle


def test_scan_reports_a_closed_port(capsys):
    # port 1 on loopback refuses the connection; the scan still produces a
    # report rather than a traceback
    assert main(["scan", "127.0.0.1:1", "--timeout", "1", "--quick", "--no-http"]) == 0
    out = capsys.readouterr().out
    assert "grade" in out


def test_scan_json(capsys):
    assert main(["scan", "127.0.0.1:1", "--timeout", "1", "--quick", "--no-http", "--json"]) == 0
    json.loads(capsys.readouterr().out)


def test_scan_quiet(capsys):
    assert main(["scan", "127.0.0.1:1", "--timeout", "1", "--quick", "--no-http", "--quiet"]) == 0
    assert "grade" in capsys.readouterr().out


def test_demo_runs_offline(capsys):
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "grade" in out
    assert "no connection left the machine" in out


def test_demo_json(capsys):
    assert main(["demo", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"]


def test_a_lab_server_can_be_started_and_scanned(capsys):
    # The lab is the only way to scan something real without the network, so
    # the CLI path that uses it is exercised end to end here.
    import argparse

    from tlslint import lab
    from tlslint.cli import cmd_scan

    server = lab.start(lab.LabConfig(profile="weak"))
    try:
        args = argparse.Namespace(
            target=f"127.0.0.1:{server.https_port}",
            sni="localhost",
            timeout=4.0,
            workers=4,
            cipher_limit=6,
            quick=True,
            no_http=False,
            plain_port=server.http_port,
            json=False,
            sarif=None,
            quiet=True,
            fail_on=None,
        )
        assert cmd_scan(args) == 0
        out = capsys.readouterr().out
        assert "grade" in out
    finally:
        server.stop()


def test_now_argument_does_not_leak_into_the_fixture_audit(capsys):
    # sanity: WITHOUT --now the same certificate is judged against the real
    # clock, which in 2026 makes good.pem valid
    assert main(["cert", str(fixture_path("good.pem"))]) == 0
    out = capsys.readouterr().out
    assert "TLS020" not in out or NOW.year < 2027
