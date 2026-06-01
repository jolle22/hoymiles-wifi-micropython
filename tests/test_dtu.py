"""
Tests for dtu.py — message framing helpers and response parsers.

MicroPython-specific imports are stubbed out before importing dtu.
The async DTU class itself is tested only for synchronous concerns
(sequence counter, argument validation, parser functions) since the
network layer requires a live socket.
"""

import sys
import os
import struct
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ---------------------------------------------------------------------------
# Stub MicroPython modules that dtu.py imports at module level or lazily
# ---------------------------------------------------------------------------

# asyncio — use stdlib asyncio (compatible for our tests)
# (already in sys.modules; no stub needed)

# logging — minimal stub (dtu uses logging.error / logging.info)
if "logging" not in sys.modules or not hasattr(sys.modules["logging"], "error"):
    # stdlib logging is fine; just ensure it's present
    import logging  # noqa: F401

# ucrc16, upb — real modules from this package (no MicroPython dependency)
# They are on sys.path via the insert above; dtu.py will find them.

# ucrypt — stub: actual crypto not needed for framing tests
import hashlib, hmac as _hmac

_ucrypt_stub = types.ModuleType("ucrypt")
def _stub_crypt_data(encrypt, enc_rand, u16_tag, u16_seq, data):
    """Identity stub — returns input unchanged (no real crypto needed for framing tests)."""
    return data
_ucrypt_stub.crypt_data = _stub_crypt_data
sys.modules["ucrypt"] = _ucrypt_stub

# Now import dtu
import dtu
from dtu import (
    _build_message, _parse_message,
    _parse_real_data_new, _parse_real_data, _parse_app_info,
    _parse_sgsmo, _parse_pvmo, _parse_metermo,
    CMD_REAL_RES_DTO, CMD_HB_RES_DTO, CMD_REAL_DATA_RES_DTO,
    CMD_HEADER, DTU,
)
from upb import PbMessage, pb_decode


# ---------------------------------------------------------------------------
# _build_message / _parse_message round-trip
# ---------------------------------------------------------------------------

class TestBuildParseRoundTrip(unittest.TestCase):
    """
    Build a message and then parse it back.
    Uses is_encrypted=False, is_extended=False for the basic path.
    """

    def _roundtrip(self, command, payload, seq=1):
        msg = _build_message(command, payload, seq,
                             is_encrypted=False, is_extended=False)
        result = _parse_message(msg, is_encrypted=False, is_extended=False,
                                enc_rand=b"", sequence=seq)
        return result

    def test_empty_payload(self):
        payload = b""
        self.assertEqual(self._roundtrip(CMD_REAL_RES_DTO, payload), payload)

    def test_short_payload(self):
        payload = b"\x01\x02\x03\x04"
        self.assertEqual(self._roundtrip(CMD_REAL_RES_DTO, payload), payload)

    def test_longer_payload(self):
        payload = bytes(range(50))
        self.assertEqual(self._roundtrip(CMD_REAL_RES_DTO, payload), payload)

    def test_sequence_in_header(self):
        payload = b"test"
        msg = _build_message(CMD_HB_RES_DTO, payload, 0xABCD,
                             is_encrypted=False, is_extended=False)
        seq_val = struct.unpack(">H", msg[4:6])[0]
        self.assertEqual(seq_val, 0xABCD)

    def test_header_starts_with_HM(self):
        msg = _build_message(CMD_REAL_RES_DTO, b"x",
                             1, is_encrypted=False, is_extended=False)
        self.assertTrue(msg.startswith(b"HM"))

    def test_command_bytes_in_header(self):
        msg = _build_message(CMD_REAL_RES_DTO, b"x",
                             1, is_encrypted=False, is_extended=False)
        self.assertEqual(msg[2:4], CMD_REAL_RES_DTO)

    def test_parse_too_short_returns_none(self):
        self.assertIsNone(_parse_message(b"\x00" * 5,
                                         is_encrypted=False, is_extended=False,
                                         enc_rand=b"", sequence=1))

    def test_parse_wrong_length_returns_none(self):
        payload = b"hello"
        msg = _build_message(CMD_REAL_RES_DTO, payload, 1,
                             is_encrypted=False, is_extended=False)
        # Trim last byte → length mismatch
        self.assertIsNone(_parse_message(msg[:-1],
                                         is_encrypted=False, is_extended=False,
                                         enc_rand=b"", sequence=1))

    def test_parse_crc_corruption_returns_none(self):
        payload = b"hello"
        msg = bytearray(_build_message(CMD_REAL_RES_DTO, payload, 1,
                                       is_encrypted=False, is_extended=False))
        # Corrupt a payload byte → CRC mismatch
        msg[-1] ^= 0xFF
        self.assertIsNone(_parse_message(bytes(msg),
                                         is_encrypted=False, is_extended=False,
                                         enc_rand=b"", sequence=1))


# ---------------------------------------------------------------------------
# _parse_sgsmo
# ---------------------------------------------------------------------------

class TestParseSgsmo(unittest.TestCase):
    def _make_raw(self, **fields):
        msg = PbMessage()
        for f, v in fields.items():
            msg.add_varint(int(f), v)
        return msg.encode()

    def test_all_zeros(self):
        raw = self._make_raw(**{str(i): 0 for i in range(1, 14)})
        result = _parse_sgsmo(raw)
        self.assertEqual(result["active_power"], 0)
        self.assertEqual(result["voltage"], 0)

    def test_specific_values(self):
        raw = self._make_raw(**{"1": 12345, "5": 999, "9": 250})
        result = _parse_sgsmo(raw)
        self.assertEqual(result["serial_number"], 12345)
        self.assertEqual(result["active_power"], 999)
        self.assertEqual(result["temperature"], 250)

    def test_keys_present(self):
        raw = b""
        result = _parse_sgsmo(raw)
        expected_keys = {"serial_number", "firmware_version", "voltage",
                         "frequency", "active_power", "reactive_power",
                         "current", "power_factor", "temperature",
                         "warning_number", "link_status", "power_limit"}
        self.assertEqual(set(result.keys()), expected_keys)


# ---------------------------------------------------------------------------
# _parse_pvmo
# ---------------------------------------------------------------------------

class TestParsePvmo(unittest.TestCase):
    def test_keys_present(self):
        result = _parse_pvmo(b"")
        expected_keys = {"serial_number", "port_number", "voltage",
                         "current", "power", "energy_total", "energy_daily",
                         "error_code"}
        self.assertEqual(set(result.keys()), expected_keys)

    def test_values(self):
        msg = PbMessage()
        msg.add_varint(1, 9999)
        msg.add_varint(5, 500)
        result = _parse_pvmo(msg.encode())
        self.assertEqual(result["serial_number"], 9999)
        self.assertEqual(result["power"], 500)


# ---------------------------------------------------------------------------
# _parse_metermo
# ---------------------------------------------------------------------------

class TestParseMetermo(unittest.TestCase):
    def test_keys_present(self):
        result = _parse_metermo(b"")
        self.assertIn("serial_number", result)
        self.assertIn("phase_total_power", result)


# ---------------------------------------------------------------------------
# _parse_real_data_new
# ---------------------------------------------------------------------------

class TestParseRealDataNew(unittest.TestCase):
    def _fields_with_sgs(self):
        """Build a fields dict with one SGSMO entry."""
        sgs_msg = PbMessage()
        sgs_msg.add_varint(5, 1000)  # active_power = 1000

        outer = PbMessage()
        outer.add_bytes(1, b"DTU-SN-001")     # device_serial_number
        outer.add_varint(2, 1700000000)        # timestamp
        outer.add_varint(12, 500)              # dtu_power
        outer.add_varint(13, 200)              # dtu_daily_energy
        outer.add_bytes(9, sgs_msg.encode())   # sgs repeated

        return pb_decode(outer.encode())

    def test_basic_structure(self):
        fields = self._fields_with_sgs()
        result = _parse_real_data_new(fields)
        self.assertEqual(result["device_serial_number"], "DTU-SN-001")
        self.assertEqual(result["dtu_power"], 500)
        self.assertEqual(result["dtu_daily_energy"], 200)
        self.assertEqual(len(result["sgs"]), 1)
        self.assertEqual(result["sgs"][0]["active_power"], 1000)

    def test_empty_fields(self):
        result = _parse_real_data_new({})
        self.assertEqual(result["sgs"], [])
        self.assertEqual(result["pv"], [])
        self.assertEqual(result["meter"], [])

    def test_non_bytes_sgs_ignored(self):
        fields = {9: [42]}   # int instead of bytes → should be skipped
        result = _parse_real_data_new(fields)
        self.assertEqual(result["sgs"], [])


# ---------------------------------------------------------------------------
# _parse_real_data (legacy)
# ---------------------------------------------------------------------------

class TestParseRealData(unittest.TestCase):
    def test_basic(self):
        pv_msg = PbMessage()
        pv_msg.add_varint(5, 300)

        outer = PbMessage()
        outer.add_bytes(1, b"LEGACY-SN")
        outer.add_varint(2, 1234567890)
        outer.add_bytes(10, pv_msg.encode())

        result = _parse_real_data(pb_decode(outer.encode()))
        self.assertEqual(result["dtu_sn"], "LEGACY-SN")
        self.assertEqual(result["timestamp"], 1234567890)
        self.assertEqual(len(result["pv"]), 1)

    def test_empty(self):
        result = _parse_real_data({})
        self.assertEqual(result["pv"], [])


# ---------------------------------------------------------------------------
# _parse_app_info
# ---------------------------------------------------------------------------

class TestParseAppInfo(unittest.TestCase):
    def test_empty(self):
        result = _parse_app_info({})
        self.assertEqual(result["dtu_serial_number"], "")
        self.assertEqual(result["dtu_info"], {})
        self.assertEqual(result["pv_info"], [])

    def test_with_dtu_info(self):
        dtu_info_msg = PbMessage()
        dtu_info_msg.add_varint(2, 100)    # sw version
        dtu_info_msg.add_varint(3, 200)    # hw version
        dtu_info_msg.add_bytes(27, b"\xab" * 16)  # enc_rand

        outer = PbMessage()
        outer.add_bytes(1, b"DTU-APP-SN")
        outer.add_bytes(8, dtu_info_msg.encode())

        result = _parse_app_info(pb_decode(outer.encode()))
        self.assertEqual(result["dtu_serial_number"], "DTU-APP-SN")
        self.assertEqual(result["dtu_info"]["dtu_sw_version"], 100)
        self.assertEqual(result["dtu_info"]["enc_rand"], b"\xab" * 16)


# ---------------------------------------------------------------------------
# DTU class — synchronous aspects
# ---------------------------------------------------------------------------

class TestDtuSequenceCounter(unittest.TestCase):
    def test_first_seq_is_one(self):
        d = DTU("127.0.0.1")
        self.assertEqual(d._next_seq(), 1)

    def test_wraps_at_0xffff(self):
        d = DTU("127.0.0.1")
        d.sequence = 0xFFFF
        self.assertEqual(d._next_seq(), 0)

    def test_increments(self):
        d = DTU("127.0.0.1")
        seqs = [d._next_seq() for _ in range(5)]
        self.assertEqual(seqs, [1, 2, 3, 4, 5])


class TestDtuSetPowerLimitValidation(unittest.TestCase):
    def test_negative_raises(self):
        d = DTU("127.0.0.1")
        import asyncio
        with self.assertRaises(ValueError):
            asyncio.get_event_loop().run_until_complete(d.set_power_limit(-1))

    def test_over_100_raises(self):
        d = DTU("127.0.0.1")
        import asyncio
        with self.assertRaises(ValueError):
            asyncio.get_event_loop().run_until_complete(d.set_power_limit(101))

    def test_zero_valid(self):
        # Should not raise ValueError (will fail at network, not validation)
        d = DTU("127.0.0.1")
        try:
            import asyncio
            asyncio.get_event_loop().run_until_complete(d.set_power_limit(0))
        except ValueError:
            self.fail("set_power_limit(0) raised ValueError unexpectedly")
        except Exception:
            pass  # Network error is expected

    def test_100_valid(self):
        d = DTU("127.0.0.1")
        try:
            import asyncio
            asyncio.get_event_loop().run_until_complete(d.set_power_limit(100))
        except ValueError:
            self.fail("set_power_limit(100) raised ValueError unexpectedly")
        except Exception:
            pass


if __name__ == "__main__":
    unittest.main()
