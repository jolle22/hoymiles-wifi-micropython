"""
Hoymiles DTU communication library for MicroPython (ESP32-C6).

Ported from hoymiles-wifi (https://github.com/suaveolent/hoymiles-wifi).
Supports: real-time data, heartbeat, power-limit control,
          inverter on/off/reboot, DTU reboot, optional AES-128-GCM encryption.

Usage
-----
    import asyncio
    from dtu import DTU

    dtu = DTU("192.168.1.100")

    async def main():
        data = await dtu.get_real_data_new()
        if data:
            for inv in data["sgs"]:
                print("Power:", inv["active_power"] / 10, "W")

    asyncio.run(main())

Encryption
----------
If your DTU uses encryption (newer firmwares), pass:
    dtu = DTU("192.168.1.100", is_encrypted=True, enc_rand=b"<16 bytes>")
You can discover enc_rand from the APPInfoData response field dtu_info.enc_rand.
"""

import struct
import time
import asyncio

from ucrc16 import crc16
from upb import (
    PbMessage, pb_decode,
    pb_get_int, pb_get_bytes, pb_get_string, pb_get_repeated,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DTU_PORT   = 10081
OFFSET     = 28800       # UTC+8 in seconds
TIMEOUT    = 10          # seconds
MIN_INTERVAL = 2         # minimum seconds between requests (Hoymiles rate limit)

CMD_HEADER = b"HM"

# Command bytes (2 bytes each, big-endian)
CMD_APP_INFO_DATA_REQ_DTO = b"\xa2\x01"
CMD_APP_INFO_DATA_RES_DTO = b"\xa3\x01"
CMD_HB_REQ_DTO            = b"\xa3\x02"
CMD_HB_RES_DTO            = b"\xa3\x02"
CMD_REAL_DATA_RES_DTO     = b"\xa3\x03"
CMD_COMMAND_RES_DTO       = b"\xa3\x05"
CMD_GET_CONFIG            = b"\xa3\x09"
CMD_REAL_RES_DTO          = b"\xa3\x11"
CMD_NETWORK_INFO_RES      = b"\xa3\x14"
CMD_CLOUD_COMMAND_RES_DTO = b"\x23\x05"

NOT_ENCRYPTED_COMMANDS = (
    CMD_APP_INFO_DATA_RES_DTO,
    CMD_APP_INFO_DATA_REQ_DTO,
    CMD_HB_REQ_DTO,
    CMD_HB_RES_DTO,
)

# Action codes for CommandResDTO
CMD_ACTION_DTU_REBOOT    = 1
CMD_ACTION_MI_START      = 6
CMD_ACTION_MI_SHUTDOWN   = 7
CMD_ACTION_LIMIT_POWER   = 8
CMD_ACTION_LIMIT_POWER   = 8

DEV_DTU = 1

# ---------------------------------------------------------------------------
# Timestamp helper
# ---------------------------------------------------------------------------

def _now_str() -> bytes:
    """Return b"YYYY-MM-DD HH:MM:SS" using localtime."""
    t = time.localtime()
    return "{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}".format(
        t[0], t[1], t[2], t[3], t[4], t[5]
    ).encode()


# ---------------------------------------------------------------------------
# Message framing helpers
# ---------------------------------------------------------------------------

def _build_message(command: bytes, payload: bytes, sequence: int,
                   is_encrypted: bool, is_extended: bool,
                   enc_rand: bytes = b"",
                   serial_number: int = 0, number: int = 0) -> bytes:
    """
    Frame a protobuf payload into a Hoymiles wire message.

    Format (normal):
        HM + cmd(2) + seq(2) + crc16(2) + length(2) + payload

    Format (extended, hybrid inverters):
        HM + cmd(2) + seq(2) + crc16(2) + outer_len(2) +
        inner_len(2) + reserved(2) + serial(8) + reserved(2) + number(2) +
        payload
    """
    if is_encrypted and not is_extended and command not in NOT_ENCRYPTED_COMMANDS:
        from ucrypt import crypt_data
        u16_tag = struct.unpack(">H", command)[0]
        payload = crypt_data(True, enc_rand, u16_tag, sequence, payload)
        crc = crc16(payload[:-16])
        length = len(payload) - 16 + 10
    else:
        crc = crc16(payload)
        length = len(payload) + 10

    header   = CMD_HEADER + command
    metadata = struct.pack(">HH", sequence, crc)

    if is_extended:
        metadata += struct.pack(">HHQHH",
                                24 + len(payload), 14,
                                serial_number, 0, number)
    else:
        metadata += struct.pack(">H", length)

    return header + metadata + payload


def _parse_message(buffer: bytes, is_encrypted: bool, is_extended: bool,
                   enc_rand: bytes, sequence: int):
    """
    Validate and unpack the payload bytes from a DTU response.
    Returns raw protobuf bytes, or None on error.
    """
    if len(buffer) < 10:
        return None

    tag_num = buffer[2:4]
    u16_tag, u16_seq = struct.unpack(">HH", buffer[2:6])
    crc_target, read_length = struct.unpack(">HH", buffer[6:10])

    # Determine expected total length
    if is_encrypted and tag_num not in NOT_ENCRYPTED_COMMANDS and not is_extended:
        expected = read_length + 16
    else:
        expected = read_length

    if len(buffer) != expected:
        return None

    if is_extended:
        payload_bytes = buffer[24:read_length]
        crc_actual = crc16(buffer[24:read_length])
    else:
        payload_bytes = buffer[10:read_length]
        crc_actual = crc16(buffer[10:read_length])

    if crc_actual != crc_target:
        return None

    if is_encrypted and tag_num not in NOT_ENCRYPTED_COMMANDS and not is_extended:
        from ucrypt import crypt_data
        ciphertext = buffer[10:expected]
        try:
            payload_bytes = crypt_data(False, enc_rand, u16_tag, u16_seq, ciphertext)
        except Exception:
            return None

    return payload_bytes


# ---------------------------------------------------------------------------
# DTU class
# ---------------------------------------------------------------------------

class DTU:
    """Async DTU communication class for MicroPython."""

    def __init__(self, host: str, is_encrypted: bool = False,
                 enc_rand: bytes = b"", timeout: int = TIMEOUT):
        self.host = host
        self.is_encrypted = is_encrypted
        self.enc_rand = enc_rand
        self.timeout = timeout
        self.sequence = 0
        self._last_request = 0
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Internal send/receive
    # ------------------------------------------------------------------

    def _next_seq(self) -> int:
        self.sequence = (self.sequence + 1) & 0xFFFF
        return self.sequence

    async def _send_request(self, command: bytes, payload: bytes,
                            is_extended: bool = False,
                            serial_number: int = 0, number: int = 0):
        """
        Send *payload* with *command*, return raw response bytes or None.
        Respects the 2-second inter-request rate limit.
        """
        seq = self._next_seq()
        message = _build_message(command, payload, seq,
                                 self.is_encrypted, is_extended,
                                 self.enc_rand,
                                 serial_number, number)

        async with self._lock:
            elapsed = time.time() - self._last_request
            if elapsed < MIN_INTERVAL:
                await asyncio.sleep(MIN_INTERVAL - elapsed)

            reader = writer = None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, DTU_PORT),
                    self.timeout
                )
                writer.write(message)
                await writer.drain()
                buffer = await asyncio.wait_for(
                    reader.read(1024), self.timeout
                )
            except Exception as e:
                print("[DTU] Connection error:", e)
                return None
            finally:
                if writer:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

            self._last_request = time.time()

        return _parse_message(buffer, self.is_encrypted, is_extended,
                              self.enc_rand, seq)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get_real_data_new(self) -> dict | None:
        """
        Query real-time inverter data (RealDataNew, CMD 0xa311).
        Returns a merged dict with keys:
          device_serial_number, timestamp, dtu_power, dtu_daily_energy,
          sgs (list of SGSMO dicts), pv (list of PvMO dicts),
          meter (list of MeterMO dicts)
        Returns None if the DTU is unreachable.
        """
        now = int(time.time())

        req = PbMessage()
        req.add_bytes(1, _now_str())   # time_ymd_hms
        req.add_varint(2, 0)            # cp = 0
        req.add_varint(4, OFFSET)       # offset
        req.add_varint(5, now)          # time

        raw = await self._send_request(CMD_REAL_RES_DTO, req.encode())
        if raw is None:
            return None

        resp = pb_decode(raw)
        total_pages = pb_get_int(resp, 3)   # ap
        combined = dict(resp)

        for cp in range(1, total_pages):
            req2 = PbMessage()
            req2.add_bytes(1, _now_str())
            req2.add_varint(2, cp)
            req2.add_varint(4, OFFSET)
            req2.add_varint(5, int(time.time()))
            raw2 = await self._send_request(CMD_REAL_RES_DTO, req2.encode())
            if raw2:
                page = pb_decode(raw2)
                for k, v in page.items():
                    if k in combined:
                        combined[k] = combined[k] + v
                    else:
                        combined[k] = v

        return _parse_real_data_new(combined)

    async def get_real_data(self) -> dict | None:
        """
        Query real-time data (legacy RealData format, CMD 0xa303).
        Returns dict with dtu_sn, pv (list) or None.
        """
        now = int(time.time())
        req = PbMessage()
        req.add_bytes(1, _now_str())
        req.add_varint(3, 0)        # package_now
        req.add_varint(4, OFFSET)   # offset
        req.add_varint(5, now)      # time

        raw = await self._send_request(CMD_REAL_DATA_RES_DTO, req.encode())
        if raw is None:
            return None
        return _parse_real_data(pb_decode(raw))

    async def heartbeat(self) -> dict | None:
        """Send heartbeat (CMD 0xa302). Returns dict or None."""
        now = int(time.time())
        req = PbMessage()
        req.add_varint(1, OFFSET)
        req.add_varint(2, now)
        req.add_bytes(3, _now_str())

        raw = await self._send_request(CMD_HB_RES_DTO, req.encode())
        if raw is None:
            return None
        f = pb_decode(raw)
        return {
            "offset": pb_get_int(f, 1),
            "time":   pb_get_int(f, 2),
            "dtu_sn": pb_get_string(f, 4),
        }

    async def get_app_info(self) -> dict | None:
        """
        Request device info (APPInfoData, CMD 0xa301).
        Returns dict with dtu_info fields.
        Note: this command is never encrypted.
        """
        now = int(time.time())
        req = PbMessage()
        req.add_bytes(1, _now_str())
        req.add_varint(2, OFFSET)
        req.add_varint(5, now)

        raw = await self._send_request(CMD_APP_INFO_DATA_RES_DTO, req.encode())
        if raw is None:
            return None
        return _parse_app_info(pb_decode(raw))

    async def get_network_info(self) -> dict | None:
        """Query DTU network status (CMD 0xa314)."""
        now = int(time.time())
        req = PbMessage()
        req.add_varint(1, OFFSET)
        req.add_varint(2, now)

        raw = await self._send_request(CMD_NETWORK_INFO_RES, req.encode())
        if raw is None:
            return None
        f = pb_decode(raw)
        return {
            "dtu_sn":         pb_get_string(f, 1),
            "net_work_mod":   pb_get_int(f, 6),
            "csq":            pb_get_int(f, 8),
            "net_work_state": pb_get_int(f, 9),
        }

    async def set_power_limit(self, percent: int) -> bool:
        """
        Set power output limit (0–100 %).
        Returns True on acknowledged response, False on error.
        """
        if not 0 <= percent <= 100:
            raise ValueError("Power limit must be 0-100")
        value = percent * 10  # DTU expects tenths of percent

        req = PbMessage()
        req.add_varint(1, int(time.time()))    # time
        req.add_varint(2, CMD_ACTION_LIMIT_POWER)  # action = 8
        req.add_varint(4, 1)                   # package_nub
        req.add_varint(6, int(time.time()))    # tid
        req.add_string(7, "A:{},B:0,C:0\r".format(value))  # data

        raw = await self._send_request(CMD_COMMAND_RES_DTO, req.encode())
        return raw is not None

    async def turn_on_inverter(self, inverter_serial: int) -> bool:
        """Start inverter. *inverter_serial* is the integer serial number."""
        return await self._inverter_command(CMD_ACTION_MI_START, inverter_serial)

    async def turn_off_inverter(self, inverter_serial: int) -> bool:
        """Shut down inverter."""
        return await self._inverter_command(CMD_ACTION_MI_SHUTDOWN, inverter_serial)

    async def reboot_dtu(self) -> bool:
        """Reboot the DTU unit."""
        req = PbMessage()
        req.add_varint(2, CMD_ACTION_DTU_REBOOT)
        req.add_varint(4, 1)
        req.add_varint(6, int(time.time()))

        raw = await self._send_request(CMD_CLOUD_COMMAND_RES_DTO, req.encode())
        return raw is not None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _inverter_command(self, action: int, serial: int) -> bool:
        """Build and send a CommandResDTO targeting a single inverter."""
        # Encode serial as varint for repeated field 9 (mi_to_sn)
        req = PbMessage()
        req.add_varint(2, action)
        req.add_varint(3, DEV_DTU)
        req.add_varint(4, 1)
        req.add_varint(6, int(time.time()))
        req.add_varint(9, serial)   # repeated int64 mi_to_sn

        raw = await self._send_request(CMD_CLOUD_COMMAND_RES_DTO, req.encode())
        return raw is not None


# ---------------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------------

def _parse_sgsmo(raw: bytes) -> dict:
    """Parse a single SGSMO sub-message (single-phase inverter)."""
    f = pb_decode(raw)
    return {
        "serial_number":   pb_get_int(f, 1),
        "firmware_version":pb_get_int(f, 2),
        "voltage":         pb_get_int(f, 3),   # ×10 V
        "frequency":       pb_get_int(f, 4),   # ×100 Hz
        "active_power":    pb_get_int(f, 5),   # ×10 W
        "reactive_power":  pb_get_int(f, 6),
        "current":         pb_get_int(f, 7),   # ×100 A
        "power_factor":    pb_get_int(f, 8),
        "temperature":     pb_get_int(f, 9),   # ×10 °C
        "warning_number":  pb_get_int(f, 10),
        "link_status":     pb_get_int(f, 12),
        "power_limit":     pb_get_int(f, 13),
    }


def _parse_pvmo(raw: bytes) -> dict:
    """Parse a PvMO sub-message (per-string PV data)."""
    f = pb_decode(raw)
    return {
        "serial_number": pb_get_int(f, 1),
        "port_number":   pb_get_int(f, 2),
        "voltage":       pb_get_int(f, 3),   # ×10 V
        "current":       pb_get_int(f, 4),   # ×100 A
        "power":         pb_get_int(f, 5),   # ×10 W
        "energy_total":  pb_get_int(f, 6),   # Wh
        "energy_daily":  pb_get_int(f, 7),   # Wh
        "error_code":    pb_get_int(f, 8),
    }


def _parse_metermo(raw: bytes) -> dict:
    f = pb_decode(raw)
    return {
        "serial_number":     pb_get_int(f, 2),
        "phase_total_power": pb_get_int(f, 3),
        "energy_total_power":pb_get_int(f, 8),
        "voltage_phase_A":   pb_get_int(f, 17),
        "current_phase_A":   pb_get_int(f, 20),
    }


def _parse_real_data_new(fields: dict) -> dict:
    """Convert raw pb_decode fields to a friendly dict."""
    sgs_raw  = pb_get_repeated(fields, 9)
    pv_raw   = pb_get_repeated(fields, 11)
    meter_raw= pb_get_repeated(fields, 6)

    sgs   = [_parse_sgsmo(r) for r in sgs_raw   if isinstance(r, (bytes, bytearray))]
    pv    = [_parse_pvmo(r)  for r in pv_raw    if isinstance(r, (bytes, bytearray))]
    meter = [_parse_metermo(r) for r in meter_raw if isinstance(r, (bytes, bytearray))]

    return {
        "device_serial_number": pb_get_string(fields, 1),
        "timestamp":            pb_get_int(fields, 2),
        "dtu_power":            pb_get_int(fields, 12),   # W
        "dtu_daily_energy":     pb_get_int(fields, 13),   # Wh
        "sgs":   sgs,
        "pv":    pv,
        "meter": meter,
    }


def _parse_pvdatamo(raw: bytes) -> dict:
    f = pb_decode(raw)
    return {
        "serial_number": pb_get_int(f, 1),
        "port":          pb_get_int(f, 2),
        "voltage":       pb_get_int(f, 3),
        "current":       pb_get_int(f, 4),
        "power":         pb_get_int(f, 5),
        "energy_total":  pb_get_int(f, 6),
        "grid_vol":      pb_get_int(f, 7),
        "grid_freq":     pb_get_int(f, 9),
        "temperature":   pb_get_int(f, 14),
        "link_status":   pb_get_int(f, 19),
    }


def _parse_real_data(fields: dict) -> dict:
    pv_raw = pb_get_repeated(fields, 10)
    pv = [_parse_pvdatamo(r) for r in pv_raw if isinstance(r, (bytes, bytearray))]
    return {
        "dtu_sn":    pb_get_string(fields, 1),
        "timestamp": pb_get_int(fields, 2),
        "pv":        pv,
    }


def _parse_app_info(fields: dict) -> dict:
    """Parse APPInfoDataReqDTO response."""
    dtu_raw = pb_get_bytes(fields, 8)
    dtu_info = {}
    if dtu_raw:
        f = pb_decode(dtu_raw)
        dtu_info = {
            "dtu_sw_version": pb_get_int(f, 2),
            "dtu_hw_version": pb_get_int(f, 3),
            "wifi_version":   pb_get_string(f, 11),
            "dfs":            pb_get_int(f, 24),
            "enc_rand":       pb_get_bytes(f, 27),
        }
    pv_raw = pb_get_repeated(fields, 11)
    pvs = []
    for r in pv_raw:
        if isinstance(r, (bytes, bytearray)):
            f = pb_decode(r)
            pvs.append({
                "pv_serial_number": pb_get_int(f, 2),
                "pv_sw_version":    pb_get_int(f, 4),
                "pv_hw_version":    pb_get_int(f, 6),
            })
    return {
        "dtu_serial_number": pb_get_string(fields, 1),
        "dtu_info": dtu_info,
        "pv_info":  pvs,
    }
