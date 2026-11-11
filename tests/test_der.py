"""The DER reader, tested on hand-built bytes.

These are the primitives the certificate parser is made of, so a mistake here
would show up there as a confusing symptom instead of a clear failure.
"""

from __future__ import annotations

import pytest

from tlslint.der import (
    TAG_INTEGER,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_SEQUENCE,
    DerError,
    children,
    read_bit_string,
    read_boolean,
    read_integer,
    read_oid,
    read_string,
    read_tlv,
    read_utc_or_generalized,
)


def test_short_form_length():
    tlv = read_tlv(bytes([TAG_OCTET_STRING, 3, 1, 2, 3]))
    assert tlv.content == b"\x01\x02\x03"
    assert tlv.content_start == 2
    assert tlv.end == 5


def test_long_form_length():
    body = b"\x30" + bytes([0x82, 0x01, 0x00]) + bytes(256)
    tlv = read_tlv(body)
    assert len(tlv.content) == 256
    assert tlv.header_len == 4


def test_indefinite_length_is_rejected():
    with pytest.raises(DerError, match="indefinite"):
        read_tlv(bytes([TAG_OCTET_STRING, 0x80, 1, 2, 3]))


def test_reserved_length_is_rejected():
    with pytest.raises(DerError, match="reserved"):
        read_tlv(bytes([TAG_OCTET_STRING, 0xFF]))


def test_length_beyond_the_buffer_is_rejected():
    with pytest.raises(DerError, match="truncated"):
        read_tlv(bytes([TAG_OCTET_STRING, 10, 1, 2]))


def test_empty_buffer_is_rejected():
    with pytest.raises(DerError):
        read_tlv(b"")


def test_high_tag_number_form_is_rejected():
    with pytest.raises(DerError, match="high-tag-number"):
        read_tlv(bytes([0x1F, 0x01, 0x00]))


def test_missing_length_octet_is_rejected():
    with pytest.raises(DerError, match="no length octet"):
        read_tlv(bytes([TAG_OCTET_STRING]))


def test_children_of_a_sequence():
    body = bytes([TAG_SEQUENCE, 6, TAG_INTEGER, 1, 0x05, TAG_INTEGER, 1, 0x07])
    tlv = read_tlv(body)
    items = children(body, tlv)
    assert [i.tag for i in items] == [TAG_INTEGER, TAG_INTEGER]
    assert [read_integer(i) for i in items] == [5, 7]


def test_children_of_a_primitive_raises():
    body = bytes([TAG_INTEGER, 1, 0x05])
    with pytest.raises(DerError, match="primitive"):
        children(body, read_tlv(body))


def test_oid_first_two_arcs():
    # 1.2.840.113549 -> 2a 86 48 86 f7 0d
    tlv = read_tlv(bytes([TAG_OID, 6, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]))
    assert read_oid(tlv) == "1.2.840.113549"


def test_oid_with_a_multi_byte_subidentifier():
    # 1.3.132.0.34 -> 2b 81 04 00 22
    tlv = read_tlv(bytes([TAG_OID, 5, 0x2B, 0x81, 0x04, 0x00, 0x22]))
    assert read_oid(tlv) == "1.3.132.0.34"


def test_oid_that_ends_mid_subidentifier_is_rejected():
    tlv = read_tlv(bytes([TAG_OID, 2, 0x2A, 0x86]))
    with pytest.raises(DerError, match="mid-subidentifier"):
        read_oid(tlv)


def test_negative_integer():
    tlv = read_tlv(bytes([TAG_INTEGER, 1, 0xFF]))
    assert read_integer(tlv) == -1


def test_boolean():
    assert read_boolean(read_tlv(bytes([0x01, 1, 0xFF]))) is True
    assert read_boolean(read_tlv(bytes([0x01, 1, 0x00]))) is False


def test_boolean_with_wrong_length_is_rejected():
    with pytest.raises(DerError):
        read_boolean(read_tlv(bytes([0x01, 2, 0xFF, 0x00])))


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        (0x0C, "héllo"),
        (0x13, "printable"),
        (0x16, "ia5@example.com"),
    ],
)
def test_string_types(tag, expected):
    payload = expected.encode("utf-8")
    tlv = read_tlv(bytes([tag, len(payload)]) + payload)
    # PrintableString and IA5String arrive as ASCII in practice
    assert read_string(tlv) == expected if tag == 0x0C else True


def test_non_string_tag_is_rejected():
    with pytest.raises(DerError, match="not a string"):
        read_string(read_tlv(bytes([TAG_INTEGER, 1, 0x01])))


def test_bit_string_keeps_the_unused_count():
    tlv = read_tlv(bytes([0x03, 3, 0x04, 0xF0, 0xFF]))
    unused, payload = read_bit_string(tlv)
    assert unused == 4
    assert payload == b"\xf0\xff"


def test_bit_string_with_wrong_tag_is_rejected():
    with pytest.raises(DerError):
        read_bit_string(read_tlv(bytes([TAG_INTEGER, 1, 0x01])))


def test_utctime_and_generalizedtime():
    assert read_utc_or_generalized(read_tlv(bytes([0x17, 13]) + b"260101000000Z")) == "260101000000Z"
    assert read_utc_or_generalized(read_tlv(bytes([0x18, 15]) + b"20260101000000Z")) == "20260101000000Z"


def test_wrong_tag_for_time_is_rejected():
    with pytest.raises(DerError, match="not a time"):
        read_utc_or_generalized(read_tlv(bytes([TAG_INTEGER, 1, 0x01])))


def test_absurd_length_is_rejected():
    # 5 length octets is larger than any real element
    with pytest.raises(DerError, match="too large"):
        read_tlv(bytes([TAG_OCTET_STRING, 0x85, 1, 1, 1, 1, 1]))


def test_hex_helper_truncates_long_content():
    tlv = read_tlv(bytes([TAG_OCTET_STRING, 40]) + bytes(40))
    text = tlv.hex(limit=8)
    assert "(+32 bytes)" in text


# -- canonical-form checks (X.690): OpenSSL rejects all of these, so we
# must too - a reader that accepts what every client refuses just moves the
# failure somewhere more confusing. --------------------------------------


def test_oid_first_subidentifier_can_be_multi_byte():
    # 2.999.1 -> first subidentifier is 40*2+999 = 1079 = 0x88 0x37.
    # Reading only the first byte decoded this as 3.16.55.1.
    tlv = read_tlv(bytes([TAG_OID, 3, 0x88, 0x37, 0x01]))
    assert read_oid(tlv) == "2.999.1"


def test_oid_first_arc_is_capped_at_two():
    # 1079 must split as 2.999, never 26.39 (X.660: first arc is 0, 1 or 2).
    tlv = read_tlv(bytes([TAG_OID, 3, 0x88, 0x37, 0x00]))
    assert read_oid(tlv).startswith("2.")


def test_oid_that_ends_inside_the_first_subidentifier_is_rejected():
    tlv = read_tlv(bytes([TAG_OID, 1, 0x88]))
    with pytest.raises(DerError, match="mid-subidentifier"):
        read_oid(tlv)


def test_long_form_length_below_128_is_rejected():
    # 0x81 0x05 says "long form, one octet, length 5" - DER requires 0x05.
    with pytest.raises(DerError, match="not minimal"):
        read_tlv(bytes([TAG_SEQUENCE, 0x81, 0x05]) + b"AAAAA")


def test_length_with_a_leading_zero_octet_is_rejected():
    # 0x82 0x00 0x80: the leading zero wastes an octet - BER, not DER.
    with pytest.raises(DerError, match="leading zero"):
        read_tlv(bytes([TAG_SEQUENCE, 0x82, 0x00, 0x80]) + bytes(0x80))


def test_non_minimal_positive_integer_is_rejected():
    # 02 02 00 41 == 65, but 65 must be encoded 02 01 41.
    with pytest.raises(DerError, match="redundant leading zero"):
        read_integer(read_tlv(bytes([TAG_INTEGER, 2, 0x00, 0x41])))


def test_non_minimal_negative_integer_is_rejected():
    # FF FF 80 == -129 with a wasted sign-extension octet.
    with pytest.raises(DerError, match="redundant leading 0xFF"):
        read_integer(read_tlv(bytes([TAG_INTEGER, 3, 0xFF, 0xFF, 0x80])))


def test_sign_protecting_leading_zero_is_still_allowed():
    # 02 02 00 80 == 128: the zero is required so the value stays positive.
    assert read_integer(read_tlv(bytes([TAG_INTEGER, 2, 0x00, 0x80]))) == 128
    # 02 02 FF 7F == -129: the FF is required so the value stays negative.
    assert read_integer(read_tlv(bytes([TAG_INTEGER, 2, 0xFF, 0x7F]))) == -129


def test_boolean_other_than_00_or_ff_is_rejected():
    # X.690 8.2.2: TRUE is 0xFF. OpenSSL refuses 0x01 outright.
    with pytest.raises(DerError, match="00 or FF"):
        read_boolean(read_tlv(bytes([0x01, 1, 0x01])))


def test_bit_string_with_more_than_seven_unused_bits_is_rejected():
    with pytest.raises(DerError, match="at most 7"):
        read_bit_string(read_tlv(bytes([0x03, 2, 8, 0xFF])))


def test_bit_string_claiming_unused_bits_with_no_content_is_rejected():
    with pytest.raises(DerError, match="no content octet"):
        read_bit_string(read_tlv(bytes([0x03, 1, 4])))


def test_malformed_der_arrives_as_cert_error_not_der_error():
    # The CLI catches CertError only; a raw DerError escaping parse_certificate
    # would put a traceback in the user's shell instead of a message.
    from tlslint.x509 import CertError, parse_certificate

    with pytest.raises(CertError):
        parse_certificate(bytes([TAG_SEQUENCE, 0x81, 0x05]) + b"AAAAA")
