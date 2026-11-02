# Contributing

**specvet** — OpenAPI / Swagger security audit — is small on purpose: hand-written parsers, deterministic rules, no dependencies. Contributions that keep it that way are welcome.

## Setup

```bash
git clone https://github.com/xuange-hu/specvet
cd specvet
pip install -e ".[mcp]" pytest ruff
pytest                 # 307 tests
ruff check src tests
```

No `pip install` is needed to run the tests after a clone — the root
`conftest.py` puts `src/` on `sys.path`.

## Rules and where they live

`src/specvet/rules.py` (SPV001…, 36 rules) with the second pass in `src/specvet/graph.py`.

## Adding a rule

1. **The entry** in `src/specvet/rules.py` with an OWASP API Top 10 2023 tag, `why` and `fix`.
2. **The check**, in `src/specvet/graph.py` if it needs more than one operation to answer.
3. **A trigger sample and a negative case** in `tests/`.
4. **A line in the demo contract**: CI asserts all 36 rules appear in the demo report.

Then update the rule table and the test-count badge in `README.md`. CI warns
when the badge and pytest disagree.

## Rules of the road

- **Zero dependencies in `src/` outside `mcp_server.py`.** `tests/test_packaging.py`
  fails on an optional import leaking into a required path.
- **No network access.** Not in the scanner, not in the tests. Tests that need
  a file write it to `tmp_path`.
- **Every finding carries a location and its source text.** A report that says
  "something is wrong" without saying where gets closed and forgotten.
- **`absent` and `empty` are different.** Decide what the explicit empty form
  means before adding a rule that fires on a missing field.
- **Line numbers come from the parser.** Do not compute them in the rule.

## Commit and PR

- One logical change per commit.
- CI runs on 3.10–3.13 across Ubuntu and Windows. A test that passes only on
  your machine will be caught there, so run `pytest` before pushing.
