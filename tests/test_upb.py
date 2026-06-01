"""Tests for upb.py — minimal protobuf encoder/decoder."""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from upb import (
    PbMessage, pb_decode,
    pb_get_int, pb_get_bytes, pb_get_string, pb_get_repeated,
    zigzag_decode, _encode_varint, _decode_varint,
    WIRE_VARINT, WIRE_LEN, WIRE_64BIT, WIRE_32BIT,
)


# ---------------------------------------------------------------------------
# Varint encode/decode
# ---------------------------------------------------------------------------

class TestEncodeVarint(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(_encode_varint(0), b"\x00")

    def test_one(self):
        self.assertEqual(_encode_varint(1), b"\x01")

    def test_127(self):
        self.assertEqual(_encode_varint(127), b"\x7f")

    def test_128_uses_two_bytes(self):
        self.assertEqual(_encode_varint(128), b"\x80\x01")

    def test_300(self):
        self.assertEqual(_encode_varint(300), b"\xac\x02")

    def test_large_value(self):
        # 2^21 = 2097152 → 3 continuation bytes + final
        encoded = _encode_varint(2097152)
        decoded, _ = _decode_varint(encoded, 0)
        self.assertEqual(decoded, 2097152)

    def test_negative_encoded_as_64bit_twos_complement(self):
        encoded = _encode_varint(-1)
        self.assertEqual(len(encoded), 10)  # 64-bit two's complement varint


class TestDecodeVarint(unittest.TestCase):
    def test_zero(self):
        val, pos = _decode_varint(b"\x00", 0)
        self.assertEqual(val, 0)
        self.assertEqual(pos, 1)

    def test_one(self):
        val, pos = _decode_varint(b"\x01", 0)
        self.assertEqual(val, 1)

    def test_multibyte(self):
        val, pos = _decode_varint(b"\xac\x02", 0)
        self.assertEqual(val, 300)
        self.assertEqual(pos, 2)

    def test_offset(self):
        data = b"\xff\x00\x01"
        val, pos = _decode_varint(data, 1)
        self.assertEqual(val, 0)
        self.assertEqual(pos, 2)

    def test_roundtrip_range(self):
        for n in [0, 1, 127, 128, 16383, 16384, 2097151, 2097152]:
            encoded = _encode_varint(n)
            decoded, _ = _decode_varint(encoded, 0)
            self.assertEqual(decoded, n)


# ---------------------------------------------------------------------------
# PbMessage encoder
# ---------------------------------------------------------------------------

class TestPbMessageAddVarint(unittest.TestCase):
    def test_field1_zero(self):
        msg = PbMessage()
        msg.add_varint(1, 0)
        # tag = (1 << 3) | 0 = 0x08; value = 0x00
        self.assertEqual(msg.encode(), b"\x08\x00")

    def test_field1_value150(self):
        msg = PbMessage()
        msg.add_varint(1, 150)
        # tag 0x08, then varint 150 = 0x96 0x01
        self.assertEqual(msg.encode(), b"\x08\x96\x01")

    def test_multiple_fields(self):
        msg = PbMessage()
        msg.add_varint(1, 1)
        msg.add_varint(2, 2)
        data = msg.encode()
        decoded = pb_decode(data)
        self.assertEqual(decoded[1], [1])
        self.assertEqual(decoded[2], [2])


class TestPbMessageAddBytes(unittest.TestCase):
    def test_empty_bytes(self):
        msg = PbMessage()
        msg.add_bytes(1, b"")
        decoded = pb_decode(msg.encode())
        self.assertEqual(decoded[1], [b""])

    def test_non_empty_bytes(self):
        msg = PbMessage()
        msg.add_bytes(2, b"hello")
        decoded = pb_decode(msg.encode())
        self.assertEqual(decoded[2], [b"hello"])


class TestPbMessageAddString(unittest.TestCase):
    def test_string_utf8(self):
        msg = PbMessage()
        msg.add_string(3, "hello")
        decoded = pb_decode(msg.encode())
        self.assertEqual(decoded[3], [b"hello"])


class TestPbMessageAddMessage(unittest.TestCase):
    def test_nested_message(self):
        inner = PbMessage()
        inner.add_varint(1, 42)

        outer = PbMessage()
        outer.add_message(5, inner)

        decoded = pb_decode(outer.encode())
        inner_bytes = decoded[5][0]
        inner_decoded = pb_decode(inner_bytes)
        self.assertEqual(inner_decoded[1], [42])


class TestPbMessageEncode(unittest.TestCase):
    def test_empty_message(self):
        self.assertEqual(PbMessage().encode(), b"")

    def test_returns_bytes(self):
        msg = PbMessage()
        msg.add_varint(1, 0)
        self.assertIsInstance(msg.encode(), bytes)


# ---------------------------------------------------------------------------
# pb_decode
# ---------------------------------------------------------------------------

class TestPbDecode(unittest.TestCase):
    def test_empty_bytes(self):
        self.assertEqual(pb_decode(b""), {})

    def test_single_varint(self):
        msg = PbMessage()
        msg.add_varint(1, 99)
        fields = pb_decode(msg.encode())
        self.assertEqual(fields[1], [99])

    def test_single_bytes_field(self):
        msg = PbMessage()
        msg.add_bytes(2, b"data")
        fields = pb_decode(msg.encode())
        self.assertEqual(fields[2], [b"data"])

    def test_repeated_field(self):
        msg = PbMessage()
        msg.add_varint(1, 10)
        msg.add_varint(1, 20)
        msg.add_varint(1, 30)
        fields = pb_decode(msg.encode())
        self.assertEqual(sorted(fields[1]), [10, 20, 30])

    def test_multiple_different_fields(self):
        msg = PbMessage()
        msg.add_varint(1, 7)
        msg.add_bytes(2, b"abc")
        msg.add_varint(3, 99)
        fields = pb_decode(msg.encode())
        self.assertEqual(fields[1], [7])
        self.assertEqual(fields[2], [b"abc"])
        self.assertEqual(fields[3], [99])

    def test_unknown_wire_type_raises(self):
        # Wire type 3 is not handled
        bad_data = bytes([0x0B])  # field 1, wire type 3
        with self.assertRaises(ValueError):
            pb_decode(bad_data)

    def test_wire_64bit_consumed(self):
        # Manually build: tag = field 1, wire 1 (64-bit), then 8 bytes
        from upb import _encode_tag
        data = _encode_tag(1, WIRE_64BIT) + b"\x01\x02\x03\x04\x05\x06\x07\x08"
        fields = pb_decode(data)
        self.assertIn(1, fields)
        self.assertEqual(fields[1][0], b"\x01\x02\x03\x04\x05\x06\x07\x08")

    def test_wire_32bit_consumed(self):
        from upb import _encode_tag
        data = _encode_tag(1, WIRE_32BIT) + b"\x01\x02\x03\x04"
        fields = pb_decode(data)
        self.assertIn(1, fields)
        self.assertEqual(fields[1][0], b"\x01\x02\x03\x04")


# ---------------------------------------------------------------------------
# Helper accessors
# ---------------------------------------------------------------------------

class TestPbHelpers(unittest.TestCase):
    def _fields(self, **kw):
        """Build decoded fields dict for helpers tests."""
        msg = PbMessage()
        for field, val in kw.items():
            num = int(field)
            if isinstance(val, int):
                msg.add_varint(num, val)
            elif isinstance(val, bytes):
                msg.add_bytes(num, val)
            elif isinstance(val, str):
                msg.add_string(num, val)
        return pb_decode(msg.encode())

    def test_pb_get_int_present(self):
        fields = self._fields(**{"1": 42})
        self.assertEqual(pb_get_int(fields, 1), 42)

    def test_pb_get_int_missing_default(self):
        self.assertEqual(pb_get_int({}, 1), 0)
        self.assertEqual(pb_get_int({}, 1, default=99), 99)

    def test_pb_get_bytes_present(self):
        fields = self._fields(**{"2": b"\xde\xad"})
        self.assertEqual(pb_get_bytes(fields, 2), b"\xde\xad")

    def test_pb_get_bytes_missing(self):
        self.assertEqual(pb_get_bytes({}, 2), b"")

    def test_pb_get_bytes_wrong_type_returns_default(self):
        # If field holds an int (not bytes), should return default
        fields = {1: [42]}
        self.assertEqual(pb_get_bytes(fields, 1), b"")

    def test_pb_get_string_present(self):
        msg = PbMessage()
        msg.add_string(3, "hello")
        fields = pb_decode(msg.encode())
        self.assertEqual(pb_get_string(fields, 3), "hello")

    def test_pb_get_string_missing(self):
        self.assertEqual(pb_get_string({}, 3), "")

    def test_pb_get_repeated_present(self):
        msg = PbMessage()
        msg.add_varint(4, 1)
        msg.add_varint(4, 2)
        msg.add_varint(4, 3)
        fields = pb_decode(msg.encode())
        self.assertEqual(sorted(pb_get_repeated(fields, 4)), [1, 2, 3])

    def test_pb_get_repeated_missing(self):
        self.assertEqual(pb_get_repeated({}, 4), [])


# ---------------------------------------------------------------------------
# Zigzag decode
# ---------------------------------------------------------------------------

class TestZigzagDecode(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(zigzag_decode(0), 0)

    def test_one_encodes_minus_one(self):
        self.assertEqual(zigzag_decode(1), -1)

    def test_two_encodes_one(self):
        self.assertEqual(zigzag_decode(2), 1)

    def test_three_encodes_minus_two(self):
        self.assertEqual(zigzag_decode(3), -2)

    def test_four_encodes_two(self):
        self.assertEqual(zigzag_decode(4), 2)

    def test_large_positive(self):
        # zigzag(2n) = n
        self.assertEqual(zigzag_decode(200), 100)

    def test_large_negative(self):
        # zigzag(2n-1) = -n
        self.assertEqual(zigzag_decode(199), -100)


if __name__ == "__main__":
    unittest.main()
