# tlslint

**审查 TLS 服务或证书，每条结论都附上证明它的字节 —— 43 条规则、自己写的 DER
解析器、本地实验室服务器、SARIF 输出。零第三方依赖。**

[![tests](https://img.shields.io/badge/tests-266%20passing-2ea44f)](https://github.com/xuange-hu/tlslint/actions)
[![python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-3776ab)](https://pypi.org/project/tlslint/)
[![dependencies](https://img.shields.io/badge/dependencies-0-2ea44f)](pyproject.toml)
[![license](https://img.shields.io/badge/license-MIT-2ea44f)](LICENSE)

```console
$ tlslint scan example.com
$ tlslint cert leaf.pem --hostname example.com
$ tlslint demo          # 不联网，五个本地服务器，43 条规则里跑出 37 条
```

---

## 三步跑通

```bash
pip install tlslint          # 不会连带装任何别的东西
tlslint scan example.com     # 或 uvx --from tlslint tlslint scan example.com
tlslint rules --category certificate
```

`scan` 是真的跟服务器握手：每个协议版本一次握手，每个候选套件一次握手，再取证书链、
在明文和 TLS 两侧各发一次 HTTP 请求。不读 banner，不猜。

## 输出长什么样

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
    serial    245393a9f604c8c606a398daf7f648358580ffc1
    validity  260101000000Z .. 360101000000Z  (3652 days)
    key       rsa 2048 bits
    signature sha256WithRSAEncryption
    names     localhost, *.localhost

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
```

每条结论四行：`where` 是位置，`saw` 是看到的实际值，`fix` 是修法，`std` 是出处。

## 为什么还要再写一个

现有的好工具要么不是 Python，要么依赖很重：`testssl.sh`（9.3k★）是 shell +
openssl，`sslyze`（3.8k★）要 `cryptography` 和 `nassl`，`sslscan`（2.6k★）是 C。
tlslint 一次 `pip install`，不需要编译器，也不需要跳板机那头有 pip 源。

四个不一样的地方：

1. **每条结论带字段和值。** 不是「证书弱」，而是
   `cert.signatureAlgorithm :: sha1WithRSAEncryption`；不是「链有问题」，而是
   「服务器只发了 1 张证书，校验证书时在 'unable to get local issuer
   certificate' 停住」。证书是在这个仓库里 DER 解析的，所以结论还能指出字节偏移。
2. **第二遍看关系。** 单看一张证书，看不出主机名没被覆盖、链首尾接不上、
   跳转是 `https → http → https`。这些是独立的规则（`TLS027`、`TLS031`、
   `TLS055`），因为修法不同。
3. **「没有」不等于「为空」。** 没有 `subjectAltName` 和 SAN 里没有 `dNSName`
   是两种错；`public access block` 整个缺失，和四个开关全部设成 false，也是
   两种错。各给一条规则。
4. **演示不需要网络。** `tlslint lab` 用随包自带的证书起一个本地 TLS 服务器，
   有五种「故意错」的配置；`tlslint demo` 把它们和随包证书一起扫一遍，43 条
   规则里跑出 37 条。剩下六条（SSLv3、RC4、3DES、NULL/export、MD5 套件、
   首尾接不上的链）由单元测试覆盖——因为现在的 OpenSSL 不肯协商它们。

## 规则

| 分类 | 条数 | 读什么 |
|---|---|---|
| `protocol` | 5 | 哪些版本能握手成功（TLS001–TLS005） |
| `cipher` | 8 | 服务器接受哪些套件、这些套件的性质（TLS010–TLS018） |
| `certificate` | 21 | DER 本身：名字、密钥、有效期、扩展、链（TLS020–TLS040） |
| `transport` | 9 | 连接之外的 HSTS、跳转、Cookie 属性（TLS050–TLS058） |

## 命令行

```console
tlslint scan example.com --json
tlslint scan example.com --sarif out.sarif
tlslint scan example.com --fail-on high   # CI 门禁：命中就退出 1
tlslint scan example.com --quick          # 只测版本和证书

tlslint cert leaf.pem chain.pem           # 完全离线
tlslint cert leaf.pem --hostname example.com
tlslint cert leaf.pem --now 2030-01-01T00:00:00+00:00

tlslint rules [--category X] [--severity Y]
tlslint lab  --profile weak               # 一个故意配错的本地服务器
tlslint demo                              # 扫五个，离线
```

## CI 门禁

```yaml
- name: TLS gate
  run: |
    tlslint scan "$HOST" --sarif tlslint.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: tlslint.sarif
```

## MCP 服务器

```bash
pip install "tlslint[mcp]"
tlslint-mcp
```

七个工具：`tlslint_scan`、`tlslint_cert`、`tlslint_rules`、`tlslint_explain`、
`tlslint_grade`、`tlslint_demo`、`tlslint_sarif`。可以在 Claude Code、Cursor、
Cline 里直接调。

## 实验室

```console
$ tlslint lab --profile weak
https://127.0.0.1:8443  (profile weak)
http://127.0.0.1:8080
```

| profile | 它错在哪 |
|---|---|
| `modern` | 基本没错，对照组 |
| `weak` | `max-age=300`、没有 `includeSubDomains`、没有 `preload`、Cookie 三个属性全无、`http → http` 跳转 |
| `legacy` | 只开 TLS 1.0 / 1.1，没有 HSTS |
| `tls13` | 只有 TLS 1.3，1.2 客户端被丢下 |
| `aes128` | 只有一个 128 位 CBC 套件，静态 RSA 密钥传输 |
| `mismatched` | 链里两张证书互不相干 |

## 测试

```bash
git clone https://github.com/xuange-hu/tlslint
cd tlslint
pip install -e ".[mcp]" pytest ruff
pytest                 # 266 tests
ruff check src tests
```

证书夹具是签进仓库的，并且围绕一个固定时刻生成，所以「25 天后过期」明年还是
25 天后过期。机器上装了 openssl 时，解析器会跟它做差分；没装的机器跳过。

参与：[CONTRIBUTING.md](CONTRIBUTING.md)。漏洞：[SECURITY.md](SECURITY.md)。

MIT 许可。
