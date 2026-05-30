"""
Minimal protobuf encoder/decoder for Hoymiles MicroPython port.

Supports only the wire types actually used in the Hoymiles protocol:
  - Varint (int32, int64, uint32, uint64, bool, enum)
  - 64-bit (fixed64, sfixed64, double) — not used here but handled
  - Length-delimited (string, bytes, embedded messages, repeated fields)
  - 32-bit (fixed32, sfixed32, float) — not used here but handled

Usage pattern
-------------
ENCODING (building a request DTO):

    msg = PbMessage()
    msg.add_bytes(1, b"2024-01-01 12:00:00")  # field 1, bytes/string
    msg.add_varint(2, 0)                       # field 2, cp=0
    msg.add_varint(4, int(time.time()))        # field 5, time
    payload = msg.encode()

DECODING (parsing a response DTO):

    fields = pb_decode(raw_bytes)
    # fields is a dict: {field_number: [value, ...]}
    # All values are raw (int for varints, bytes for length-delimited).
    # Repeated fields have multiple entries in the list.
    device_sn = fields.get(1, [b""])[0].decode()
    timestamp  = fields.get(2, [0])[0]
    sgs_list   = [pb_decode(b) for b in fields.get(9, [])]
"""

import struct


# ---------------------------------------------------------------------------
# Wire types
# ---------------------------------------------------------------------------
WIRE_VARINT = 0
WIRE_64BIT  = 1
WIRE_LEN    = 2
WIRE_32BIT  = 5


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------

def _encode_varint(value: int) -> bytes:
    """Encode a non-negative integer as a protobuf varint."""
    if value < 0:
        # Encode negative as 64-bit two's complement (10 bytes)
        value = value & 0xFFFFFFFFFFFFFFFF
    out = bytearray()
    while True:
        bits = value & 0x7F
        value >>= 7
        if value:
            out.append(bits | 0x80)
        else:
            out.append(bits)
            break
    return bytes(out)


def _encode_tag(field: int, wire_type: int) -> bytes:
    return _encode_varint((field << 3) | wire_type)


class PbMessage:
    """Incremental protobuf message builder."""

    def __init__(self):
        self._buf = bytearray()

    def add_varint(self, field: int, value: int):
        self._buf += _encode_tag(field, WIRE_VARINT)
        self._buf += _encode_varint(value)

    def add_bytes(self, field: int, value: bytes):
        self._buf += _encode_tag(field, WIRE_LEN)
        self._buf += _encode_varint(len(value))
        self._buf += value

    def add_string(self, field: int, value: str):
        self.add_bytes(field, value.encode('utf-8'))

    def add_message(self, field: int, sub: 'PbMessage'):
        self.add_bytes(field, sub.encode())

    def encode(self) -> bytes:
        return bytes(self._buf)


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

def _decode_varint(data: bytes, pos: int):
    """Return (value, new_pos)."""
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    return result, pos


def pb_decode(data: bytes) -> dict:
    """
    Decode a serialised protobuf message.

    Returns dict mapping field_number -> list of values.
    Varint fields: int values.
    Length-delimited fields: bytes values (caller decodes sub-messages).
    """
    fields = {}
    pos = 0
    n = len(data)
    while pos < n:
        tag, pos = _decode_varint(data, pos)
        field = tag >> 3
        wire  = tag & 0x07

        if wire == WIRE_VARINT:
            val, pos = _decode_varint(data, pos)
        elif wire == WIRE_LEN:
            length, pos = _decode_varint(data, pos)
            val = data[pos:pos + length]
            pos += length
        elif wire == WIRE_64BIT:
            val = data[pos:pos + 8]
            pos += 8
        elif wire == WIRE_32BIT:
            val = data[pos:pos + 4]
            pos += 4
        else:
            raise ValueError("Unknown wire type: {}".format(wire))

        if field not in fields:
            fields[field] = []
        fields[field].append(val)

    return fields


def pb_get_int(fields: dict, field: int, default: int = 0) -> int:
    return fields.get(field, [default])[0]


def pb_get_bytes(fields: dict, field: int, default: bytes = b'') -> bytes:
    v = fields.get(field, [default])[0]
    return v if isinstance(v, (bytes, bytearray)) else default


def pb_get_string(fields: dict, field: int, default: str = '') -> str:
    v = pb_get_bytes(fields, field)
    return v.decode('utf-8') if v else default


def pb_get_repeated(fields: dict, field: int) -> list:
    return fields.get(field, [])


def zigzag_decode(n: int) -> int:
    """Decode zigzag-encoded sint32/sint64."""
    return (n >> 1) ^ -(n & 1)
