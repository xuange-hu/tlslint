#!/usr/bin/env bash
# Regenerate every certificate fixture under tests/fixtures and
# src/tlslint/data. Run it from the repository root:
#
#     bash tools/make_fixtures.sh
#
# The fixtures are checked in so the tests and the CI jobs never need network
# access or a particular OpenSSL version. The only requirement for regenerating
# them is OpenSSL 3.5 or later, which is where -not_before / -not_after landed.
set -euo pipefail

cd "$(dirname "$0")/.."
FIX=tests/fixtures
DATA=src/tlslint/data
mkdir -p "$FIX" "$DATA"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# A throwaway CA so the leaf certificates carry a real authority key id and a
# chain that can be tested.
openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
  -not_before 20260101000000Z -not_after 20460101000000Z \
  -keyout "$TMP/ca.key" -out "$FIX/ca.pem" \
  -subj "/C=US/O=tlslint/CN=tlslint test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

issue() {
  # issue <name> <key-spec> <digest> <not_before> <not_after> [extfile]
  local name=$1 keyspec=$2 digest=$3 nb=$4 na=$5 ext=${6:-}
  if [ "$keyspec" = "rsa2048" ]; then
    openssl genrsa -out "$TMP/$name.key" 2048 2>/dev/null
  elif [ "$keyspec" = "rsa1024" ]; then
    openssl genrsa -out "$TMP/$name.key" 1024 2>/dev/null
  else
    openssl ecparam -name "$keyspec" -genkey -noout -out "$TMP/$name.key" 2>/dev/null
  fi
  openssl req -new -key "$TMP/$name.key" -out "$TMP/$name.csr" \
    -subj "/C=US/O=tlslint/CN=$name.example.com" 2>/dev/null
  local args=(-req -in "$TMP/$name.csr" -CA "$FIX/ca.pem" -CAkey "$TMP/ca.key"
    -set_serial "0x$(printf '%x' "$RANDOM""$RANDOM")" -"$digest"
    -not_before "$nb" -not_after "$na" -out "$FIX/$name.pem")
  if [ -n "$ext" ]; then
    args+=(-extfile "$ext")
  fi
  openssl x509 "${args[@]}" 2>/dev/null
}

cat > "$TMP/good.ext" <<'EXT'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:good.example.com,DNS:www.good.example.com
authorityInfoAccess=OCSP;URI:http://ocsp.example.com/,caIssuers;URI:http://ca.example.com/ca.crt
crlDistributionPoints=URI:http://crl.example.com/ca.crl
EXT

cp "$TMP/good.ext" "$TMP/sha1.ext"
cp "$TMP/good.ext" "$TMP/rsa1024.ext"
cp "$TMP/good.ext" "$TMP/ec384.ext"
cp "$TMP/good.ext" "$TMP/long.ext"
cp "$TMP/good.ext" "$TMP/expired.ext"
cp "$TMP/good.ext" "$TMP/notyet.ext"

cat > "$TMP/cnonly.ext" <<'EXT'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
authorityInfoAccess=OCSP;URI:http://ocsp.example.com/
crlDistributionPoints=URI:http://crl.example.com/ca.crl
EXT

cat > "$TMP/wildcard.ext" <<'EXT'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:*.example.com
EXT

cat > "$TMP/clientauth.ext" <<'EXT'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:client.example.com
EXT

cat > "$TMP/noaia.ext" <<'EXT'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:noaia.example.com
EXT

cat > "$TMP/caleaf.ext" <<'EXT'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectAltName=DNS:caleaf.example.com
EXT

cat > "$TMP/ku.ext" <<'EXT'
basicConstraints=CA:FALSE
keyUsage=critical,keyCertSign
extendedKeyUsage=serverAuth
subjectAltName=DNS:ku.example.com
authorityInfoAccess=OCSP;URI:http://ocsp.example.com/
crlDistributionPoints=URI:http://crl.example.com/ca.crl
EXT

cat > "$TMP/dup.ext" <<'EXT'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:dup.example.com,DNS:dup.example.com
authorityInfoAccess=OCSP;URI:http://ocsp.example.com/
crlDistributionPoints=URI:http://crl.example.com/ca.crl
EXT

cat > "$TMP/cnsplit.ext" <<'EXT'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:other.example.com
authorityInfoAccess=OCSP;URI:http://ocsp.example.com/
crlDistributionPoints=URI:http://crl.example.com/ca.crl
EXT

cat > "$TMP/lab.ext" <<'EXT'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1
EXT

issue good    rsa2048 sha256 20260101000000Z 20270101000000Z "$TMP/good.ext"
issue sha1    rsa2048 sha1   20260101000000Z 20270101000000Z "$TMP/sha1.ext"
issue rsa1024 rsa1024 sha256 20260101000000Z 20270101000000Z "$TMP/rsa1024.ext"
issue ec384   secp384r1 sha256 20260101000000Z 20270101000000Z "$TMP/ec384.ext"
issue cnonly  rsa2048 sha256 20260101000000Z 20270101000000Z "$TMP/cnonly.ext"
issue wildcard rsa2048 sha256 20260101000000Z 20270101000000Z "$TMP/wildcard.ext"
issue clientauth rsa2048 sha256 20260101000000Z 20270101000000Z "$TMP/clientauth.ext"
issue noaia   rsa2048 sha256 20260101000000Z 20270101000000Z "$TMP/noaia.ext"
issue caleaf  rsa2048 sha256 20260101000000Z 20270101000000Z "$TMP/caleaf.ext"
issue long    rsa2048 sha256 20260101000000Z 20280101000000Z "$TMP/long.ext"
issue expired rsa2048 sha256 20200101000000Z 20200201000000Z "$TMP/expired.ext"
issue notyet  rsa2048 sha256 20990101000000Z 20990201000000Z "$TMP/notyet.ext"
# Expires 25 days after the fixed "now" the demo and the tests use.
issue soon    rsa2048 sha256 20260101000000Z 20260626000000Z "$TMP/good.ext"
issue ku      rsa2048 sha256 20260101000000Z 20270101000000Z "$TMP/ku.ext"
issue dup     rsa2048 sha256 20260101000000Z 20270101000000Z "$TMP/dup.ext"
issue cnsplit rsa2048 sha256 20260101000000Z 20270101000000Z "$TMP/cnsplit.ext"
issue ec256k1 secp256k1 sha256 20260101000000Z 20270101000000Z "$TMP/good.ext"

# A certificate whose two copies of the signature algorithm disagree. OpenSSL
# cannot be asked to produce one, so the inner AlgorithmIdentifier is retagged
# from sha256WithRSAEncryption to sha384WithRSAEncryption: same length, so the
# DER stays well formed and only the meaning changes.
python - "$FIX" <<'PY'
import base64, sys

fix = sys.argv[1]
sha256 = bytes.fromhex("06092a864886f70d01010b")
sha384 = bytes.fromhex("06092a864886f70d01010c")
with open(f"{fix}/good.pem", "rb") as fh:
    text = fh.read().decode()
body = "".join(line for line in text.splitlines() if "-----" not in line)
der = base64.b64decode(body)
index = der.find(sha256)
assert index != -1, "sha256WithRSAEncryption not found in the good fixture"
patched = der[:index] + sha384 + der[index + len(sha256) :]
encoded = base64.encodebytes(patched).decode().replace("\n", "")
with open(f"{fix}/mismatch.pem", "w", encoding="utf-8") as fh:
    fh.write("-----BEGIN CERTIFICATE-----\n")
    for start in range(0, len(encoded), 64):
        fh.write(encoded[start : start + 64] + "\n")
    fh.write("-----END CERTIFICATE-----\n")
print("  fixtures: mismatch.pem (retagged signature algorithm)")
PY

# A self-signed leaf: issuer == subject and the key id points at itself.
openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
  -not_before 20260101000000Z -not_after 20270101000000Z \
  -keyout "$TMP/selfsigned.key" -out "$FIX/selfsigned.pem" \
  -subj "/C=US/O=tlslint/CN=selfsigned.example.com" \
  -addext "basicConstraints=CA:FALSE" \
  -addext "subjectAltName=DNS:selfsigned.example.com" 2>/dev/null

# The lab server certificate: shipped with the package so `tlslint lab` and the
# CI demo job can run a real TLS server without touching the network.
openssl genrsa -out "$DATA/lab.key" 2048 2>/dev/null
openssl req -new -key "$DATA/lab.key" -out "$TMP/lab.csr" \
  -subj "/C=US/O=tlslint/CN=localhost" 2>/dev/null
openssl x509 -req -in "$TMP/lab.csr" -signkey "$DATA/lab.key" -sha256 -days 7300 \
  -not_before 20260101000000Z -not_after 20360101000000Z \
  -extfile "$TMP/lab.ext" -out "$DATA/lab.pem" 2>/dev/null

# The lab's mismatched chain: the lab leaf followed by a CA that did not issue
# it, so the scanner can see a chain whose links do not couple.
cat "$DATA/lab.pem" "$FIX/ca.pem" > "$DATA/mismatched.pem"

# A bundle of two unrelated certificates, and a leaf-plus-CA chain.
cat "$FIX/good.pem" "$FIX/selfsigned.pem" > "$FIX/bundle.pem"
cat "$FIX/good.pem" "$FIX/ca.pem" > "$FIX/chain.pem"

# A PEM that is truncated on purpose, and one that is not a certificate at all.
head -c 400 "$FIX/good.pem" > "$FIX/truncated.pem"
printf -- "-----BEGIN CERTIFICATE-----\nnot base64 at all !!!\n-----END CERTIFICATE-----\n" > "$FIX/broken.pem"

# The demo ships its own copy of the fixtures it needs: a pip-installed package
# has no tests/ directory to read them from.
mkdir -p "$DATA/demo"
for name in expired notyet soon long sha1 rsa1024 cnonly wildcard selfsigned noaia clientauth caleaf dup mismatch ec256k1 cnsplit ku good; do
  cp "$FIX/$name.pem" "$DATA/demo/$name.pem"
done

ls -1 "$FIX" | sed 's/^/  fixtures: /'
ls -1 "$DATA" | sed 's/^/  data:     /'
