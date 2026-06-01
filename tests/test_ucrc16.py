"""Tests for ucrc16.py — CRC-16/ARC (poly=0x8005, reflected, init=0xFFFF)."""

import sys
import os
import unittest

# Make the package root importable from any working directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ucrc16


class TestCrc16Table(unittest.TestCase):
    def setUp(self):
        # Reset the lazy table so each test starts clean
        ucrc16._TABLE = None

    def test_table_is_none_before_first_call(self):
        self.assertIsNone(ucrc16._TABLE)

    def test_table_is_built_after_first_call(self):
        ucrc16.crc16(b"x")
        self.assertIsNotNone(ucrc16._TABLE)
        self.assertEqual(len(ucrc16._TABLE), 256)

    def test_table_entries_are_16bit(self):
        ucrc16.crc16(b"x")
        for v in ucrc16._TABLE:
            self.assertGreaterEqual(v, 0)
            self.assertLessEqual(v, 0xFFFF)


class TestCrc16KnownVectors(unittest.TestCase):
    """
    Reference values produced by:
        import crcmod
        fn = crcmod.mkCrcFun(0x18005, rev=True, initCrc=0xFFFF, xorOut=0x0000)
    """

    def test_empty(self):
        # CRC of empty input = initial value 0xFFFF
        self.assertEqual(ucrc16.crc16(b""), 0xFFFF)

    def test_single_zero_byte(self):
        self.assertEqual(ucrc16.crc16(b"\x00"), 0x40BF)

    def test_single_0xff(self):
        self.assertEqual(ucrc16.crc16(b"\xff"), 0x00FF)

    def test_123456789(self):
        self.assertEqual(ucrc16.crc16(b"123456789"), 0x4B37)

    def test_hello(self):
        self.assertEqual(ucrc16.crc16(b"Hello"), 0xF377)

    def test_all_zeros_4_bytes(self):
        self.assertEqual(ucrc16.crc16(b"\x00\x00\x00\x00"), 0x2400)


class TestCrc16Properties(unittest.TestCase):
    def test_result_is_int(self):
        self.assertIsInstance(ucrc16.crc16(b"abc"), int)

    def test_result_fits_16_bits(self):
        for data in [b"", b"\x00", b"\xff" * 100, b"arbitrary data"]:
            result = ucrc16.crc16(data)
            self.assertGreaterEqual(result, 0)
            self.assertLessEqual(result, 0xFFFF)

    def test_idempotent(self):
        data = b"same data"
        self.assertEqual(ucrc16.crc16(data), ucrc16.crc16(data))

    def test_different_inputs_usually_differ(self):
        self.assertNotEqual(ucrc16.crc16(b"aaa"), ucrc16.crc16(b"bbb"))

    def test_table_reused_across_calls(self):
        ucrc16.crc16(b"first")
        table_id = id(ucrc16._TABLE)
        ucrc16.crc16(b"second")
        self.assertEqual(id(ucrc16._TABLE), table_id)

    def test_bytearray_input(self):
        self.assertEqual(ucrc16.crc16(bytearray(b"123456789")), 0x4B37)


if __name__ == "__main__":
    unittest.main()
