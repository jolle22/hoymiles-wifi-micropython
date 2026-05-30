"""
AES-128-GCM encrypt/decrypt for encrypted Hoymiles DTUs.

Requires MicroPython firmware built with ucryptolib (AES) and uhashlib (SHA-256).
Both are included in standard ESP32 MicroPython builds.

Key derivation:   SHA256(SHA256(SHA256(enc_rand)))[:16]
Nonce derivation: SHA256(SHA256(SHA256(tag_le + seq_le + enc_rand)))[-12:]
AAD:              struct.pack("<HH", tag, seq)

Note: MicroPython's ucryptolib provides AES in CTR mode but NOT GCM natively.
      GCM = CTR + GHASH.  This module implements GHASH in pure Python, which is
      slow but functional.  On an ESP32-C6 @ 160 MHz a typical message (~100 B)
      takes roughly 80-120 ms.  For 2-second polling this is fine.
"""

import struct
import uhashlib


# ---------------------------------------------------------------------------
# SHA-256 helpers
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    h = uhashlib.sha256()
    h.update(data)
    return h.digest()


def _sha256x3(data: bytes) -> bytes:
    return _sha256(_sha256(_sha256(data)))


def derive_aes_128_key(enc_rand: bytes) -> bytes:
    return _sha256x3(enc_rand)[:16]


def derive_nonce(enc_rand: bytes, u16_tag: int, u16_seq: int) -> bytes:
    buf = struct.pack("<HH", u16_tag, u16_seq) + enc_rand  # 20 bytes
    return _sha256x3(buf)[-12:]


# ---------------------------------------------------------------------------
# GF(2^128) multiply for GHASH
# ---------------------------------------------------------------------------
# Irreducible polynomial: x^128 + x^7 + x^2 + x + 1  (0xE1 in MSB form)

def _gf_mul(X: int, Y: int) -> int:
    """Multiply two 128-bit integers in GF(2^128)."""
    Z = 0
    V = X
    R = 0xE1000000000000000000000000000000
    for i in range(128):
        if Y & (1 << (127 - i)):
            Z ^= V
        if V & 1:
            V = (V >> 1) ^ R
        else:
            V >>= 1
    return Z


def _ghash(H: int, data: bytes) -> int:
    """Compute GHASH_H(data). data must already be padded to 16-byte boundary."""
    Y = 0
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        Xi = int.from_bytes(block, 'big')
        Y = _gf_mul(Y ^ Xi, H)
    return Y


# ---------------------------------------------------------------------------
# AES-128 (ECB) via ucryptolib
# ---------------------------------------------------------------------------

def _aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    import ucryptolib
    aes = ucryptolib.aes(key, 1)  # mode 1 = ECB
    return aes.encrypt(block)


# ---------------------------------------------------------------------------
# AES-128-GCM
# ---------------------------------------------------------------------------

def _ctr_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate CTR keystream starting at counter=2 (GCM convention)."""
    import ucryptolib
    out = bytearray()
    # Initial counter block J0 = nonce || 0x00000001
    # CTR starts at J0+1 = nonce || 0x00000002
    counter = 2
    while len(out) < length:
        cb = nonce + struct.pack(">I", counter)
        out += bytearray(_aes_ecb_encrypt(key, cb))
        counter += 1
    return bytes(out[:length])


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _pad16(data: bytes) -> bytes:
    r = len(data) % 16
    return data + b'\x00' * (16 - r if r else 0)


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Return ciphertext + 16-byte auth tag."""
    # Subkey H = AES(K, 0^128)
    H = int.from_bytes(_aes_ecb_encrypt(key, b'\x00' * 16), 'big')

    # Encrypt
    ks = _ctr_keystream(key, nonce, len(plaintext))
    ciphertext = _xor_bytes(plaintext, ks)

    # Auth tag
    auth_data = (_pad16(aad) + _pad16(ciphertext) +
                 struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8))
    S = _ghash(H, auth_data)

    # E(K, J0)
    j0 = nonce + b'\x00\x00\x00\x01'
    ej0 = int.from_bytes(_aes_ecb_encrypt(key, j0), 'big')
    tag = (S ^ ej0).to_bytes(16, 'big')

    return ciphertext + tag


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext_tag: bytes, aad: bytes) -> bytes:
    """Return plaintext.  Raises ValueError on authentication failure."""
    if len(ciphertext_tag) < 16:
        raise ValueError("ciphertext too short")
    ciphertext = ciphertext_tag[:-16]
    tag_received = ciphertext_tag[-16:]

    H = int.from_bytes(_aes_ecb_encrypt(key, b'\x00' * 16), 'big')

    auth_data = (_pad16(aad) + _pad16(ciphertext) +
                 struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8))
    S = _ghash(H, auth_data)
    j0 = nonce + b'\x00\x00\x00\x01'
    ej0 = int.from_bytes(_aes_ecb_encrypt(key, j0), 'big')
    tag_computed = (S ^ ej0).to_bytes(16, 'big')

    if tag_computed != tag_received:
        raise ValueError("AES-GCM auth tag mismatch")

    ks = _ctr_keystream(key, nonce, len(ciphertext))
    return _xor_bytes(ciphertext, ks)


# ---------------------------------------------------------------------------
# Public API (mirrors hoymiles_wifi/crypt_util.py)
# ---------------------------------------------------------------------------

def crypt_data(encrypt: bool, enc_rand: bytes, u16_tag: int, u16_seq: int,
               input_data: bytes) -> bytes:
    key = derive_aes_128_key(enc_rand)
    nonce = derive_nonce(enc_rand, u16_tag, u16_seq)
    aad = struct.pack("<HH", u16_tag, u16_seq)
    if encrypt:
        return aes_gcm_encrypt(key, nonce, input_data, aad)
    else:
        return aes_gcm_decrypt(key, nonce, input_data, aad)
