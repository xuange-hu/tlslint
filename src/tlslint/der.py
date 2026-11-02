"""A DER reader that remembers where every element started.

Every finding this project reports carries a byte offset, so the reader has to
keep offsets rather than handing back bare values. It is deliberately minimal:
definite-length TLVs, no BER (a certificate is DER by definition), no implicit
tag games beyond the two places X.509 actually uses them.
"""

from __future__ import annotations

from dataclasses import dataclass

TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_SET = 0x31

# Character string types a certificate can carry in a Name or a URI.
STRING_TAGS = {
    0x0C: "utf-8",  # UTF8String
    0x13: "ascii",  # PrintableString
    0x16: "ascii",  # IA5String
    0x14: "latin-1",  # T61String / TeletexString
    0x1E: "utf-16-be",  # BMPString
    0x1A: "ascii",  # VisibleString
}


class DerError(ValueError):
    """The bytes are not the DER the caller expected."""


@dataclass
class Tlv:
    """One TLV. ``start`` is the offset of the identifier octet."""

    tag: int
    start: int
    header_len: int
    content: bytes

    @property
    def end(self) -> int:
        return self.start + self.header_len + len(self.content)

    @property
    def content_start(self) -> int:
        return self.start + self.header_len

    def hex(self, limit: int = 24) -> str:
        shown = self.content[:limit]
        text = shown.hex()
        if len(self.content) > limit:
            text += f"... (+{len(self.content) - limit} bytes)"
        return text


def read_tlv(buf: bytes, offset: int = 0) -> Tlv:
    """Read one TLV at ``offset``."""
    if offset >= len(buf):
        raise DerError(f"truncated: no identifier octet at {offset}")
    tag = buf[offset]
    if tag & 0x1F == 0x1F:
        raise DerError(f"high-tag-number form at {offset} is not used by X.509")
    pos = offset + 1
    if pos >= len(buf):
        raise DerError(f"truncated: no length octet at {pos}")
    first = buf[pos]
    pos += 1
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise DerError(f"indefinite length at {offset}: BER, not DER")
    elif first == 0xFF:
        raise DerError(f"reserved length octet at {offset}")
    else:
        count = first & 0x7F
        if count > 4:
            raise DerError(f"length at {offset} is {count} octets: too large to be real")
        if pos + count > len(buf):
            raise DerError(f"truncated: length at {offset} runs past the buffer")
        length = int.from_bytes(buf[pos : pos + count], "big")
        pos += count
    if pos + length > len(buf):
        raise DerError(f"truncated: element at {offset} claims {length} bytes, {len(buf) - pos} remain")
    return Tlv(tag=tag, start=offset, header_len=pos - offset, content=buf[pos : pos + length])


def children(buf: bytes, tlv: Tlv) -> list[Tlv]:
    """The TLVs directly inside a constructed element."""
    if not tlv.tag & 0x20:
        raise DerError(f"element at {tlv.start} is primitive and has no children")
    out: list[Tlv] = []
    pos = tlv.content_start
    while pos < tlv.end:
        item = read_tlv(buf, pos)
        out.append(item)
        pos = item.end
    return out


def read_boolean(tlv: Tlv) -> bool:
    if tlv.tag != TAG_BOOLEAN or len(tlv.content) != 1:
        raise DerError(f"not a boolean at {tlv.start}")
    return tlv.content[0] != 0


def read_integer(tlv: Tlv) -> int:
    if tlv.tag != TAG_INTEGER or not tlv.content:
        raise DerError(f"not an integer at {tlv.start}")
    return int.from_bytes(tlv.content, "big", signed=True)


def read_oid(tlv: Tlv) -> str:
    if tlv.tag != TAG_OID or not tlv.content:
        raise DerError(f"not an OID at {tlv.start}")
    data = tlv.content
    first = data[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    started = False
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7F)
        started = True
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
            started = False
    if started:
        raise DerError(f"OID at {tlv.start} ends mid-subidentifier")
    return ".".join(parts)


def read_string(tlv: Tlv) -> str:
    if tlv.tag in STRING_TAGS:
        return tlv.content.decode(STRING_TAGS[tlv.tag], errors="replace")
    raise DerError(f"not a string at {tlv.start}: tag 0x{tlv.tag:02x}")


def read_utc_or_generalized(tlv: Tlv) -> str:
    """The raw time text. Callers turn it into a datetime and report failures."""
    if tlv.tag == 0x17:  # UTCTime
        return tlv.content.decode("ascii", errors="replace")
    if tlv.tag == 0x18:  # GeneralizedTime
        return tlv.content.decode("ascii", errors="replace")
    raise DerError(f"not a time at {tlv.start}: tag 0x{tlv.tag:02x}")


def read_bit_string(tlv: Tlv) -> tuple[int, bytes]:
    """(unused bits, payload)."""
    if tlv.tag != TAG_BIT_STRING or not tlv.content:
        raise DerError(f"not a bit string at {tlv.start}")
    unused = tlv.content[0]
    return unused, tlv.content[1:]
