"""Packaging contract: the console scripts must not need an optional extra.

CI installs `.[mcp]`, so a missing base dependency is invisible there and only
shows up as ModuleNotFoundError for whoever runs `tlslint`. These assertions
are static, which is the only way to check a claim about an environment you are
not in.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: tomllib landed in 3.11
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _pytoml as tomllib  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
SRC = ROOT / "src" / "tlslint"
SRCROOT = ROOT / "src"


def _pyproject() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def _scripts() -> dict[str, str]:
    return _pyproject()["project"]["scripts"]


def _target_path(script: str) -> Path:
    module = script.split(":", 1)[0]
    return SRCROOT / Path(module.replace(".", "/") + ".py")


def _collect_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            out.add(node.module.split(".")[0])
    return out


def test_console_scripts_exist():
    scripts = _scripts()
    assert "tlslint" in scripts
    assert "tlslint-mcp" in scripts


def test_every_console_script_target_module_resolves():
    for name, target in _scripts().items():
        assert _target_path(target).exists(), f"{name} -> {target} is missing"


def test_stdlib_only_imports_in_cli_entrypoint():
    """`tlslint` must run with zero third-party packages installed."""
    stdlib = set(sys.stdlib_module_names) | {"__future__"}
    imports = _collect_imports(SRC / "cli.py")
    third_party = {i for i in imports if i not in stdlib and i != "tlslint"}
    assert third_party == set(), f"cli.py pulls in {third_party}"


def test_every_core_module_imports_without_third_party_packages():
    """The zero-dependency claim is about the whole core, not just the CLI."""
    stdlib = set(sys.stdlib_module_names) | {"__future__"}
    offenders: dict[str, set[str]] = {}
    for path in sorted(SRC.glob("*.py")):
        if path.name == "mcp_server.py":
            continue
        third_party = {i for i in _collect_imports(path) if i not in stdlib and i != "tlslint"}
        if third_party:
            offenders[path.name] = third_party
    assert offenders == {}, offenders


def test_mcp_server_imports_mcp_only_inside_build():
    tree = ast.parse((SRC / "mcp_server.py").read_text(encoding="utf-8"))
    top_level: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            top_level.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            top_level.add(node.module.split(".")[0])
    assert "mcp" not in top_level
    assert "def build_server" in (SRC / "mcp_server.py").read_text(encoding="utf-8")


def test_mcp_extra_pins_below_2():
    """mcp 2.x renamed FastMCP to MCPServer; this server is written for 1.x."""
    extras = _pyproject()["project"]["optional-dependencies"]["mcp"]
    assert any("mcp>=1" in d and "<2" in d for d in extras), extras


def test_base_dependencies_are_empty():
    assert _pyproject()["project"].get("dependencies", []) == []


def test_version_matches_init():
    version = _pyproject()["project"]["version"]
    assert f'__version__ = "{version}"' in (SRC / "__init__.py").read_text(encoding="utf-8")


def test_src_layout_is_used():
    cfg = _pyproject()
    assert cfg["tool"]["setuptools"]["package-dir"].get("") == "src"


def test_package_data_includes_the_lab_certificates():
    """`tlslint lab` and `tlslint demo` read these from an installed package."""
    data = _pyproject()["tool"]["setuptools"]["package-data"]["tlslint"]
    assert any(pattern.startswith("data/") and pattern.endswith("*.pem") for pattern in data)
    assert "data/*.key" in data


def test_requires_python_matches_the_ci_matrix():
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    requires = _pyproject()["project"]["requires-python"]
    for version in ("3.10", "3.11", "3.12", "3.13"):
        assert version in text, f"CI does not test {version}, but requires-python is {requires}"


def _full_environment() -> bool:
    """The badge is only meaningful where every module collects.

    Two things shrink the collection count on some legs without anything being
    wrong: test_mcp.py needs the optional `mcp` package, and
    test_pytoml_parity.py needs `tomllib` (3.11+). A module skipped at import
    time contributes zero collected tests, so the count is environment-dependent
    by construction. Comparing it anywhere but a complete install produced a
    week of false alarms, so the check is skipped unless both are available.
    """
    import importlib.util

    if sys.version_info < (3, 11):
        return False
    return importlib.util.find_spec("mcp") is not None


@pytest.mark.skipif(
    not _full_environment(),
    reason="badge count is validated where every test module collects",
)
def test_readme_test_count_matches_collection():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    m = re.search(r"tests-(\d+)%20passing", readme)
    assert m, "README is missing the tests badge"
    declared = int(m.group(1))
    collected = _collected_tests()
    assert declared == collected, f"README says {declared}, pytest collects {collected}"


def _collected_tests() -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-o", "addopts=", str(ROOT / "tests")],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    m = re.search(r"(\d+) tests? collected", proc.stdout)
    if m is None:
        pytest.skip(f"could not collect tests: {proc.stdout[-200:]} {proc.stderr[-200:]}")
    return int(m.group(1))
