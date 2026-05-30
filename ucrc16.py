"""
CRC-16 implementation for Hoymiles protocol.

Equivalent to: crcmod.mkCrcFun(0x18005, rev=True, initCrc=0xFFFF, xorOut=0x0000)

Polynomial : 0x8005 (reflected)
Init       : 0xFFFF
RefIn/Out  : True
XorOut     : 0x0000
"""

# Pre-computed reflected CRC-16/ARC (poly=0x8005) table
_TABLE = None


def _build_table():
    global _TABLE
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
        table.append(crc)
    _TABLE = table


def crc16(data: bytes) -> int:
    """Return CRC-16 of *data* (poly=0x8005, reflected, init=0xFFFF)."""
    if _TABLE is None:
        _build_table()
    crc = 0xFFFF
    for byte in data:
        crc = (crc >> 8) ^ _TABLE[(crc ^ byte) & 0xFF]
    return crc
