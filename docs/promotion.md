# Promotion drafts

Written, not sent. Posting anywhere is a decision for the maintainer, not for
the automation that wrote the copy.

## One line

> tlslint — audit a TLS server or a certificate and get the bytes that prove
> each finding. 43 rules, zero dependencies.

## Show HN

Title: `Show HN: tlslint – TLS and X.509 audit with the bytes that prove each finding`

Body:

```
I got tired of TLS reports that say "weak configuration" without saying which
field is weak, so I wrote a scanner where every finding carries the field and
the value: cert.signatureAlgorithm :: sha1WithRSAEncryption, or "the server
sent 1 certificate and validation stopped with 'unable to get local issuer
certificate'".

The interesting part was not the rules, it was making them reproducible:

- The certificate is DER-parsed in the repo (no cryptography, no openssl
  subprocess), so a finding can point at a byte offset.
- A second pass reads relationships instead of objects: hostname against SAN,
  leaf against chain, HTTP redirect against the TLS connection underneath.
- `tlslint lab` starts a local TLS server with a bundled self-signed cert and
  five deliberately wrong configurations. `tlslint demo` scans all five plus
  the shipped certificate fixtures and fires 37 of the 43 rules with no
  network at all. The other six (SSLv3, RC4, 3DES, NULL/export, MD5, an
  uncoupled chain) are covered by unit tests, because no current OpenSSL will
  negotiate them.
- Certificates are judged against a fixed clock, so a fixture that "expires in
  25 days" still expires in 25 days next year.

Zero dependencies, MIT, 266 tests. It also ships an MCP server so you can ask
Claude Code or Cursor to scan and explain.
```

## Reddit — r/netsec

Title: `tlslint: TLS/X.509 audit in zero-dependency Python, every finding carries its evidence`

Points to hit, in this order:

1. What it is: one `pip install`, `tlslint scan host`.
2. The evidence format: `where / saw / fix / std` for every finding.
3. The lab and the offline demo: five local servers, no network, 37/43 rules.
4. The honest limitation: protocol and cipher coverage depends on the local
   OpenSSL, which is why the demo asserts consistency rather than presence for
   those rules.

## Reddit — r/selfhosted

Angle: a TLS gate you can run in CI and in a cron job. `--fail-on high` exits
1, `--sarif` writes something GitHub code scanning will read. No agent, no
account, no compiler.

## Product Hunt

Tagline: `TLS and certificate audit that shows its work`
Description: 120 characters on the evidence format, then the three commands.

## X thread

1. `tlslint scan example.com` — a TLS audit that shows its work: every finding
   is `where / saw / fix / std`.
2. The certificate is DER-parsed in the repo, so findings can cite a byte
   offset. No cryptography, no openssl subprocess.
3. `tlslint lab` starts a local TLS server that is wrong on purpose, five ways.
   `tlslint demo` scans all five with no network: 37 of 43 rules fire.
4. Zero dependencies. 266 tests. MIT. Also an MCP server.

## Awesome-list blurb

```
- [tlslint](https://github.com/xuange-hu/tlslint) - TLS and X.509 audit with
  evidence for every finding: 43 rules, zero dependencies, SARIF, a local lab
  server for offline demos. Python.
```
