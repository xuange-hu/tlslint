# tlslint

**Audit a TLS server or a certificate and get the bytes that prove each
finding — 43 rules, a DER reader written from scratch, a local lab server,
SARIF for CI. Zero dependencies.**

[![tests](https://img.shields.io/badge/tests-266%20passing-2ea44f)](https://github.com/xuange-hu/tlslint/actions)
[![python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-3776ab)](https://pypi.org/project/tlslint/)
[![dependencies](https://img.shields.io/badge/dependencies-0-2ea44f)](pyproject.toml)
[![license](https://img.shields.io/badge/license-MIT-2ea44f)](LICENSE)

```console
$ tlslint scan example.com
$ tlslint cert leaf.pem --hostname example.com
$ tlslint demo          # no network, five local servers, 37 of the 43 rules
```

---

## Three commands, sixty seconds

```bash
pip install tlslint          # nothing else is installed with it
tlslint scan example.com     # or: uvx --from tlslint tlslint scan example.com
tlslint rules --category certificate
```

`scan` is a real conversation with the server: one handshake per protocol
version, one handshake per candidate cipher suite, the certificate chain, and
one HTTP request on each side. It does not read a banner and guess.

<details open>
<summary><code>tlslint scan</code> against the bundled weak lab server</summary>

```console
tlslint 0.1.0  host:127.0.0.1:14568

grade E    13 finding(s)   high 4  medium 2  low 6  info 1

  . default handshake: TLSv1.3 with TLS_AES_256_GCM_SHA384 (256-bit)
  . versions accepted: TLSv1.2, TLSv1.3
  . 5 suites accepted; strongest is 256 bits
  . chain: 1 certificate(s), incomplete
  . chain validation said: certificate verify failed: self-signed certificate

  certificate
    subject   C=US,O=tlslint,CN=localhost
    issuer    C=US,O=tlslint,CN=localhost
    serial    245393a9f604c8c606a398daf7f648358580ffc1
    validity  260101000000Z .. 360101000000Z  (3652 days)
    key       rsa 2048 bits
    signature sha256WithRSAEncryption
    names     localhost, *.localhost

  versions
    SSLv3    refused
    TLSv1.0  refused   ([SSL: NO_CIPHERS_AVAILABLE] no ciphers available)
    TLSv1.1  refused   ([SSL: NO_CIPHERS_AVAILABLE] no ciphers available)
    TLSv1.2  accepted
    TLSv1.3  accepted

  suites accepted
    ECDHE-RSA-AES256-GCM-SHA384              TLSv1.2   256-bit  AEAD    FS
    ECDHE-RSA-AES256-SHA384                  TLSv1.2   256-bit  cbc     FS
    ECDHE-RSA-CHACHA20-POLY1305              TLSv1.2   256-bit  AEAD    FS
    ECDHE-RSA-AES128-GCM-SHA256              TLSv1.2   128-bit  AEAD    FS
    ECDHE-RSA-AES128-SHA256                  TLSv1.2   128-bit  cbc     FS

  HIGH
  ! TLS029  The certificate is self-signed
      where  host:127.0.0.1:14568/chain[0] :: cert.issuer
      saw    issuer == subject == C=US,O=tlslint,CN=localhost
      fix    Use a certificate from a CA the clients already trust.
      std    OWASP ASVS 9.1.2
  ! TLS030  The server did not send the intermediate certificates
      where  host:127.0.0.1:14568 :: chain
      saw    the server sent 1 certificate(s) and validation stopped with
             'unable to get local issuer certificate'
      fix    Send the full chain, leaf first, with the intermediate after it.
      std    RFC 5246 7.4.2
  ! TLS054  Plain HTTP does not redirect to HTTPS
      where  host:127.0.0.1:14568 :: http.redirect
      saw    http://127.0.0.1 answered 302 and pointed at http://127.0.0.1:14569/second
      fix    Answer HTTP with a 301 to the HTTPS URL.
      std    OWASP ASVS 9.1.1
```

</details>

## Why another TLS scanner

The good ones are not Python, or not dependency-free, or not readable line by
line: `testssl.sh` (9.3k★) is shell plus openssl, `sslyze` (3.8k★) needs
`cryptography` and `nassl`, `sslscan` (2.6k★) is C. tlslint is one `pip
install`, no compiler, no package index on the far side of the jump host.

Four things it does differently:

1. **Every finding carries the field and the value.** Not "weak certificate"
   but `cert.signatureAlgorithm :: sha1WithRSAEncryption`, and not "bad chain"
   but *"the server sent 1 certificate and validation stopped with 'unable to
   get local issuer certificate'"*. The certificate is DER-parsed in this
   repository, so a finding can also point at a byte offset.
2. **A second pass reads the relationships.** One certificate cannot tell you
   the hostname is not covered, the chain does not link issuer to subject, or
   that the redirect goes `https → http → https`. Those are separate rules
   (`TLS027`, `TLS031`, `TLS055`) because they have separate fixes.
3. **Absent is not the same as empty.** A certificate with no
   `subjectAltName` is a different mistake from one whose SAN holds no
   `dNSName`; a `public access block` that is missing is a different mistake
   from one that sets all four flags to false. Both pairs get separate rules.
4. **The demo runs on your machine with no network.** `tlslint lab` starts a
   local TLS server with a bundled certificate and five different wrong
   configurations; `tlslint demo` scans all of them plus the shipped
   certificate fixtures and fires 37 of the 43 rules. The remaining six (SSLv3,
   RC4, 3DES, NULL/export, MD5 suites, and a chain that does not couple) are
   named by unit tests, because no current OpenSSL will negotiate them.

## The rules

| category | rules | what it reads |
|---|---|---|
| `protocol` | 5 | which versions complete a handshake (TLS001–TLS005) |
| `cipher` | 8 | which suites the server accepts, and their properties (TLS010–TLS018) |
| `certificate` | 21 | the DER: names, keys, validity, extensions, chain (TLS020–TLS040) |
| `transport` | 9 | HSTS, redirects, cookie attributes around the connection (TLS050–TLS058) |

```console
$ tlslint rules --severity critical
$ tlslint rules --category certificate
```

Every rule names the standard it comes from and the fix for it, and CI asserts
the demo still exercises the ones that can fire offline.

## Command line

```console
tlslint scan example.com                  # host, host:port or [ipv6]:port
tlslint scan example.com --json
tlslint scan example.com --sarif out.sarif
tlslint scan example.com --fail-on high   # exit 1 for a CI gate
tlslint scan example.com --quick          # versions and certificate only

tlslint cert leaf.pem chain.pem           # offline: no connection at all
tlslint cert leaf.pem --hostname example.com
tlslint cert leaf.pem --now 2030-01-01T00:00:00+00:00

tlslint rules [--category X] [--severity Y]
tlslint lab  --profile weak               # a local server that is wrong on purpose
tlslint demo                              # scan five of them, offline
```

`--fail-on` makes it a gate: `tlslint scan host --fail-on high` exits 1 when
anything at `high` or worse is present.

## CI

```yaml
- name: TLS gate
  run: |
    tlslint scan "$HOST" --sarif tlslint.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: tlslint.sarif
```

## MCP server

```bash
pip install "tlslint[mcp]"
tlslint-mcp
```

Seven tools, registered by name: `tlslint_scan`, `tlslint_cert`,
`tlslint_rules`, `tlslint_explain`, `tlslint_grade`, `tlslint_demo`,
`tlslint_sarif`. Use it from Claude Code, Cursor or Cline:

> *scan example.com and explain anything you find at high or above*

## The lab

```console
$ tlslint lab --profile weak
https://127.0.0.1:8443  (profile weak)
http://127.0.0.1:8080
```

| profile | what it gets wrong |
|---|---|
| `modern` | nothing much — the control |
| `weak` | `max-age=300`, no `includeSubDomains`, no `preload`, unflagged cookies, `http → http` redirect |
| `legacy` | TLS 1.0 and 1.1, no HSTS |
| `tls13` | TLS 1.3 only, so 1.2 clients are stranded |
| `aes128` | one 128-bit CBC suite with static RSA key transport |
| `mismatched` | a chain whose two certificates have nothing to do with each other |

## How it is built

```
src/tlslint/
  der.py        definite-length DER reader that keeps every offset
  oids.py       the OIDs a certificate actually shows up with
  x509.py       PEM/DER → facts (names, keys, validity, extensions)
  probe.py      handshakes, suite enumeration, chain, one HTTP request
  rules.py      43 rules, each with a standard and a fix
  analyze.py    two passes: one object at a time, then the relationships
  render.py     the report a person reads
  sarif.py      SARIF 2.1.0
  lab.py        a TLS server you run on purpose
  demo.py       offline: five servers plus the shipped fixtures
  cli.py        argparse entry point
  mcp_server.py seven MCP tools (lazy import of the optional extra)
```

The only third-party package in the whole picture is `mcp`, and it is optional.

## Tests

```bash
git clone https://github.com/xuange-hu/tlslint
cd tlslint
pip install -e ".[mcp]" pytest ruff
pytest                 # 266 tests
ruff check src tests
```

The certificate fixtures are checked in and dated around a fixed instant, so
"expires in 25 days" stays true next year. Where openssl is installed the
reader is diffed against it; where it is not, those tests skip.

Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md). Vulnerabilities:
[SECURITY.md](SECURITY.md).

MIT licensed.
