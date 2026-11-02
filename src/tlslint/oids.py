"""Object identifiers that a TLS audit has to be able to name.

Only the OIDs a certificate or a handshake actually shows up with are here.
A missing name degrades to the dotted form rather than raising, so an unknown
OID is never the reason a scan fails.
"""

from __future__ import annotations

# Attribute types in a Name (X.501 / RFC 4519 / PKCS#9).
ATTRIBUTES: dict[str, str] = {
    "2.5.4.3": "CN",
    "2.5.4.4": "SN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "STREET",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "title",
    "2.5.4.97": "organizationIdentifier",
    "2.5.4.15": "businessCategory",
    "2.5.4.17": "postalCode",
    "0.9.2342.19200300.100.1.1": "UID",
    "0.9.2342.19200300.100.1.25": "DC",
    "1.2.840.113549.1.9.1": "emailAddress",
    "1.3.6.1.4.1.311.60.2.1.2": "jurisdictionC",
    "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionST",
}

# Signature algorithms. The value is (digest, key type) because the two halves
# are graded separately: a SHA-256 signature on a 1024-bit RSA key is a
# different problem from a SHA-1 signature on a 4096-bit one.
SIGNATURE_ALGORITHMS: dict[str, tuple[str, str]] = {
    "1.2.840.113549.1.1.2": ("md2", "rsa"),
    "1.2.840.113549.1.1.4": ("md5", "rsa"),
    "1.2.840.113549.1.1.5": ("sha1", "rsa"),
    "1.2.840.113549.1.1.11": ("sha256", "rsa"),
    "1.2.840.113549.1.1.12": ("sha384", "rsa"),
    "1.2.840.113549.1.1.13": ("sha512", "rsa"),
    "1.2.840.113549.1.1.14": ("sha224", "rsa"),
    "1.2.840.113549.1.1.10": ("rsassa-pss", "rsa"),
    "1.2.840.10040.4.3": ("sha1", "dsa"),
    "1.2.840.10040.4.1": ("", "dsa"),
    "1.2.840.10045.4.1": ("sha1", "ecdsa"),
    "1.2.840.10045.4.3.2": ("sha256", "ecdsa"),
    "1.2.840.10045.4.3.3": ("sha384", "ecdsa"),
    "1.2.840.10045.4.3.4": ("sha512", "ecdsa"),
    "1.3.101.112": ("", "ed25519"),
    "1.3.101.113": ("", "ed448"),
    "1.2.840.113549.1.1.1": ("", "rsa"),
}

# Digests that are no longer acceptable on a public certificate.
WEAK_DIGESTS = {"md2", "md5", "sha1"}

# Public key algorithms.
PUBLIC_KEY_ALGORITHMS: dict[str, str] = {
    "1.2.840.113549.1.1.1": "rsa",
    "1.2.840.113549.1.1.10": "rsa-pss",
    "1.2.840.10040.4.1": "dsa",
    "1.2.840.10045.2.1": "ec",
    "1.3.101.112": "ed25519",
    "1.3.101.113": "ed448",
    "1.2.840.113549.1.1.19": "",  # (placeholder never emitted; keeps lookups total)
}

# Named curves. secp256k1 is listed not because it is broken but because no
# public CA will issue on it, so seeing one is worth naming.
CURVES: dict[str, str] = {
    "1.2.840.10045.3.1.7": "prime256v1",
    "1.3.132.0.34": "secp384r1",
    "1.3.132.0.35": "secp521r1",
    "1.3.132.0.33": "secp224r1",
    "1.3.132.0.10": "secp256k1",
    "1.3.36.3.3.2.8.1.1.7": "brainpoolP256r1",
    "1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1",
    "1.3.36.3.3.2.8.1.1.13": "brainpoolP512r1",
    "1.2.840.10045.3.1.1": "secp192r1",
}

# Curves below 256 bits, or that no public trust store accepts.
WEAK_CURVES = {"secp192r1", "secp224r1", "secp256k1"}

# Extensions.
EXTENSIONS: dict[str, str] = {
    "2.5.29.9": "subjectDirectoryAttributes",
    "2.5.29.14": "subjectKeyIdentifier",
    "2.5.29.15": "keyUsage",
    "2.5.29.16": "privateKeyUsagePeriod",
    "2.5.29.17": "subjectAltName",
    "2.5.29.18": "issuerAltName",
    "2.5.29.19": "basicConstraints",
    "2.5.29.30": "nameConstraints",
    "2.5.29.31": "CRLDistributionPoints",
    "2.5.29.32": "certificatePolicies",
    "2.5.29.33": "policyMappings",
    "2.5.29.35": "authorityKeyIdentifier",
    "2.5.29.36": "policyConstraints",
    "2.5.29.37": "extKeyUsage",
    "2.5.29.46": "freshestCRL",
    "2.5.29.54": "inhibitAnyPolicy",
    "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
    "1.3.6.1.5.5.7.1.11": "subjectInfoAccess",
    "1.3.6.1.4.1.11129.2.4.2": "signedCertificateTimestampList",
    "1.3.6.1.5.5.7.1.24": "tlsFeature",
}

# Key usage bits, in the order they appear in the BIT STRING.
KEY_USAGE_BITS = [
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
]

# Extended key usage OIDs worth naming.
EXTENDED_KEY_USAGES: dict[str, str] = {
    "2.5.29.37.0": "anyExtendedKeyUsage",
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.5.5.7.3.9": "OCSPSigning",
}

# Access methods inside authorityInfoAccess.
ACCESS_METHODS: dict[str, str] = {
    "1.3.6.1.5.5.7.48.1": "ocsp",
    "1.3.6.1.5.5.7.48.2": "caIssuers",
    "1.3.6.1.5.5.7.48.3": "timeStamping",
    "1.3.6.1.5.5.7.48.5": "caRepository",
}

# GeneralName tags inside subjectAltName / CRLDistributionPoints / AIA.
GENERAL_NAME_TAGS: dict[int, str] = {
    0: "otherName",
    1: "rfc822Name",
    2: "dNSName",
    3: "x400Address",
    4: "directoryName",
    5: "ediPartyName",
    6: "URI",
    7: "iPAddress",
    8: "registeredID",
}


def name(oid: str, table: dict[str, str]) -> str:
    """The short name for an OID, or the dotted form when it is unknown."""
    return table.get(oid, oid)
