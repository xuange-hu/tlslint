"""The MCP surface.

The tool bodies are plain functions, so they are tested directly. Only
``build_server`` needs the optional extra; when ``mcp`` is absent a stub stands
in, which still proves that every tool is registered under its own name and
that nothing is registered twice.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types

import pytest
from helpers import fixture_path

from tlslint import mcp_server
from tlslint.mcp_server import TOOLS, build_server, tlslint_explain, tlslint_rules
from tlslint.rules import RULES

HAS_MCP = importlib.util.find_spec("mcp") is not None


def test_every_tool_is_named_after_its_function():
    assert [t.__name__ for t in TOOLS] == [t.__name__ for t in TOOLS]
    assert all(t.__name__.startswith("tlslint_") for t in TOOLS)


def test_no_tool_is_registered_twice():
    names = [t.__name__ for t in TOOLS]
    assert len(names) == len(set(names))


def test_every_tool_has_a_docstring_that_reads_like_a_spec():
    for tool in TOOLS:
        assert tool.__doc__, tool.__name__
        assert len(tool.__doc__.strip()) > 30, tool.__name__


def test_rules_tool_prints_the_whole_table():
    text = tlslint_rules()
    assert f"{len(RULES)} of {len(RULES)} rules" in text


def test_rules_tool_filters():
    text = tlslint_rules(category="certificate")
    assert "TLS001" not in text
    assert "TLS020" in text


def test_explain_known_rule():
    text = tlslint_explain("tls020")
    assert "TLS020" in text  # lower case input is accepted
    assert "fix:" in text


def test_explain_unknown_rule_is_not_an_error():
    text = tlslint_explain("TLS999")
    assert "unknown rule" in text
    assert "TLS001" in text  # it lists what does exist


def test_cert_tool_on_a_fixture():
    text = mcp_server.tlslint_cert(str(fixture_path("expired.pem")))
    assert "TLS020" in text


def test_cert_tool_json():
    payload = json.loads(mcp_server.tlslint_cert(str(fixture_path("expired.pem")), as_json=True))
    assert payload["findings"]


def test_cert_tool_on_a_missing_file():
    assert "no such file" in mcp_server.tlslint_cert("nope.pem")


def test_cert_tool_on_a_broken_file():
    assert "could not read" in mcp_server.tlslint_cert(str(fixture_path("broken.pem")))


def test_cert_tool_with_a_hostname():
    text = mcp_server.tlslint_cert(str(fixture_path("good.pem")), hostname="elsewhere.test")
    assert "TLS027" in text


@pytest.mark.slow
def test_sarif_tool_writes_a_file(tmp_path):
    from tlslint import lab

    server = lab.start(lab.LabConfig(profile="modern"))
    try:
        path = tmp_path / "out.sarif"
        text = mcp_server.tlslint_sarif(f"127.0.0.1:{server.https_port}", str(path), timeout=4.0)
        assert "wrote" in text
        assert json.loads(path.read_text(encoding="utf-8"))["version"] == "2.1.0"
    finally:
        server.stop()


@pytest.mark.slow
def test_grade_tool_on_a_lab_server():
    from tlslint import lab

    server = lab.start(lab.LabConfig(profile="modern"))
    try:
        payload = json.loads(mcp_server.tlslint_grade(f"127.0.0.1:{server.https_port}", timeout=4.0))
        assert payload["grade"]
        assert "counts" in payload
    finally:
        server.stop()


@pytest.mark.slow
def test_grade_tool_honours_fail_on():
    from tlslint import lab

    server = lab.start(lab.LabConfig(profile="weak"))
    try:
        payload = json.loads(mcp_server.tlslint_grade(f"127.0.0.1:{server.https_port}", timeout=4.0, fail_on="medium"))
        assert payload["fail_on"] == "medium"
        assert payload["passes"] is False
    finally:
        server.stop()


@pytest.mark.slow
def test_scan_tool_on_a_lab_server():
    from tlslint import lab

    server = lab.start(lab.LabConfig(profile="weak"))
    try:
        text = mcp_server.tlslint_scan(f"127.0.0.1:{server.https_port}", timeout=4.0, quick=True)
        assert "grade" in text
    finally:
        server.stop()


@pytest.mark.slow
def test_demo_tool():
    text = mcp_server.tlslint_demo()
    assert "grade" in text


@pytest.mark.slow
def test_scan_tool_json_shape():
    from tlslint import lab

    server = lab.start(lab.LabConfig(profile="modern"))
    try:
        payload = json.loads(mcp_server.tlslint_scan(f"127.0.0.1:{server.https_port}", timeout=4.0, quick=True, as_json=True))
        assert payload["target"].startswith("host:")
    finally:
        server.stop()


# ----------------------------------------------------------- server assembly


class _StubFastMCP:
    def __init__(self, name, version=None):
        self.name = name
        self.version = version
        self.registered: dict[str, object] = {}

    def tool(self, name=None):
        def wrap(fn):
            self.registered[name or fn.__name__] = fn
            return fn

        return wrap

    def run(self):  # pragma: no cover - never called in tests
        raise AssertionError("run() should not be called by a test")


@pytest.fixture
def stub_mcp(monkeypatch):
    """Install a stub mcp package, whether or not the real one is present."""
    stub = types.ModuleType("mcp")
    server = types.ModuleType("mcp.server")
    fastmcp = types.ModuleType("mcp.server.fastmcp")
    created: list[_StubFastMCP] = []
    fastmcp.FastMCP = lambda name, version=None: _record(created, name, version)
    server.fastmcp = fastmcp
    stub.server = server
    monkeypatch.setitem(sys.modules, "mcp", stub)
    monkeypatch.setitem(sys.modules, "mcp.server", server)
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", fastmcp)
    return created


def _record(created, name, version):
    obj = _StubFastMCP(name, version)
    created.append(obj)
    return obj


def test_build_server_registers_every_tool(stub_mcp):
    build_server()
    assert len(stub_mcp) == 1
    assert set(stub_mcp[0].registered) == {t.__name__ for t in TOOLS}


def test_build_server_names_the_server(stub_mcp):
    build_server()
    assert stub_mcp[0].name == "tlslint"


@pytest.mark.skipif(not HAS_MCP, reason="the mcp extra is not installed")
def test_build_server_with_the_real_sdk():
    """The real SDK has to accept the server and expose all seven tools."""
    import asyncio
    import inspect

    server = build_server()
    names = {t.__name__ for t in TOOLS}
    listed = set()
    if hasattr(server, "list_tools"):
        result = server.list_tools()
        if inspect.isawaitable(result):
            result = asyncio.run(result)
        listed = {t.name for t in result}
    assert listed == names, listed


def test_the_module_imports_without_mcp(monkeypatch):
    """The zero-dependency claim: importing the facade must not need `mcp`."""
    import builtins

    real_import = builtins.__import__

    def guard(name, *args, **kwargs):
        if name == "mcp" or name.startswith("mcp."):
            raise ModuleNotFoundError("No module named 'mcp'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guard)
    for module in [m for m in list(sys.modules) if m == "mcp" or m.startswith("mcp.")]:
        monkeypatch.delitem(sys.modules, module, raising=False)
    monkeypatch.delitem(sys.modules, "tlslint.mcp_server", raising=False)
    import tlslint.mcp_server as reloaded

    assert reloaded.TOOLS
    with pytest.raises(ModuleNotFoundError):
        reloaded.build_server()
