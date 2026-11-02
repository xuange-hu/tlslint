# Security policy

## Scope

**specvet** — OpenAPI / Swagger security audit — is a static analysis tool: it reads **OpenAPI 3.x and Swagger 2.0 documents in JSON or YAML** and prints a report.
The security questions that apply to it are the ones that apply to any tool
that parses untrusted input.

Supported: the current release.

## What this tool does with your files

Nothing leaves your machine. There is no network client in the scanning path:
the tool opens the files you point it at, parses them, and writes a report.
It never writes to the files it reads.

## Reporting a vulnerability in specvet

Use [GitHub private vulnerability reporting](https://github.com/xuange-hu/specvet/security/advisories)
on the Security tab. If private reporting is unavailable to you, open an issue
marked `security`.

Include:

1. the version (`specvet --version`);
2. the input that triggers it — the actual file is preferred over a description;
3. what you expected and what happened.

For a parse failure, the smallest input that reproduces it is the whole report.

## What counts as a vulnerability here

- **A security scheme that is read as present when nothing references it.** `securitySchemes` defined and unreferenced looks like authentication and is not.
- **A line number that is off by one.** JSON and YAML are read by two hand-written parsers; a wrong line sends the reader to the wrong operation.
- **A document construct that is silently dropped** — a flow mapping inside a sequence item, for instance.
- **A path that escapes the directory it was pointed at.**

## What does not count

- A rule firing on input you consider correct. That is a false positive: open
  an issue with the sample and it gets a regression test.
- A rule you want added. Open an issue or a PR.

## Timing

I triage within a week and will confirm receipt. If a fix needs to sit in a
branch for a while, the advisory goes out when the fix lands, not before.
