"""
Tests for ucrypt.py — AES-128-GCM encryption/decryption.

MicroPython-specific modules are stubbed out:
  - uhashlib  → stdlib hashlib.sha256
  - ucryptolib → cryptography.hazmat AES-ECB

Run with:
    pip install cryptography
    python -m pytest tests/test_ucrypt.py
"""

import sys
import os
import struct
import hashlib
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ---------------------------------------------------------------------------
# Stub: uhashlib  (wraps stdlib hashlib)
# ---------------------------------------------------------------------------

class _Sha256Stub:
    def __init__(self):
        self._h = hashlib.sha256()

    def update(self, data):
        self._h.update(data)

    def digest(self):
        return self._h.digest()


_uhashlib_stub = types.ModuleType("uhashlib")
_uhashlib_stub.sha256 = _Sha256Stub
sys.modules["uhashlib"] = _uhashlib_stub


# ---------------------------------------------------------------------------
# Stub: ucryptolib  (wraps cryptography.hazmat AES-ECB)
# ---------------------------------------------------------------------------

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    class _AesStub:
        def __init__(self, key, mode):
            if mode != 1:
                raise ValueError("Only ECB (mode 1) supported in stub")
            # Fresh encryptor per instance (stateful — do not reuse across blocks)
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            self._enc = cipher.encryptor()

        def encrypt(self, block):
            return self._enc.update(block)

    _ucryptolib_stub = types.ModuleType("ucryptolib")
    _ucryptolib_stub.aes = _AesStub
    sys.modules["ucryptolib"] = _ucryptolib_stub
    CRYPTOGRAPHY_AVAILABLE = True

except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Now import (or reload) the module under test.
# Force a reload so that if another test module registered a ucrypt stub
# earlier (e.g. test_dtu.py), we get the real source file.
# ---------------------------------------------------------------------------

import importlib
import ucrypt
importlib.reload(ucrypt)


# ---------------------------------------------------------------------------
# SHA-256 helpers
# ---------------------------------------------------------------------------

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography package required")
class TestSha256Helpers(unittest.TestCase):
    def test_sha256_returns_32_bytes(self):
        result = ucrypt._sha256(b"hello")
        self.assertEqual(len(result), 32)

    def test_sha256_known_vector(self):
        # SHA-256("") = e3b0c44298fc1c149afb...
        expected = hashlib.sha256(b"").digest()
        self.assertEqual(ucrypt._sha256(b""), expected)

    def test_sha256x3_is_nested(self):
        data = b"test"
        expected = hashlib.sha256(hashlib.sha256(hashlib.sha256(data).digest()).digest()).digest()
        self.assertEqual(ucrypt._sha256x3(data), expected)


# ---------------------------------------------------------------------------
# Key and nonce derivation
# ---------------------------------------------------------------------------

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography package required")
class TestKeyNonceDerivation(unittest.TestCase):
    ENC_RAND = b"0123456789abcdef"   # 16 arbitrary bytes

    def test_derive_aes_128_key_is_16_bytes(self):
        key = ucrypt.derive_aes_128_key(self.ENC_RAND)
        self.assertEqual(len(key), 16)

    def test_derive_aes_128_key_is_bytes(self):
        key = ucrypt.derive_aes_128_key(self.ENC_RAND)
        self.assertIsInstance(key, bytes)

    def test_derive_nonce_is_12_bytes(self):
        nonce = ucrypt.derive_nonce(self.ENC_RAND, 0xA311, 1)
        self.assertEqual(len(nonce), 12)

    def test_derive_nonce_is_bytes(self):
        nonce = ucrypt.derive_nonce(self.ENC_RAND, 0xA311, 1)
        self.assertIsInstance(nonce, bytes)

    def test_derive_key_deterministic(self):
        k1 = ucrypt.derive_aes_128_key(self.ENC_RAND)
        k2 = ucrypt.derive_aes_128_key(self.ENC_RAND)
        self.assertEqual(k1, k2)

    def test_derive_nonce_deterministic(self):
        n1 = ucrypt.derive_nonce(self.ENC_RAND, 0x0001, 5)
        n2 = ucrypt.derive_nonce(self.ENC_RAND, 0x0001, 5)
        self.assertEqual(n1, n2)

    def test_different_enc_rand_gives_different_key(self):
        k1 = ucrypt.derive_aes_128_key(b"0123456789abcdef")
        k2 = ucrypt.derive_aes_128_key(b"fedcba9876543210")
        self.assertNotEqual(k1, k2)

    def test_different_seq_gives_different_nonce(self):
        n1 = ucrypt.derive_nonce(self.ENC_RAND, 0xA311, 1)
        n2 = ucrypt.derive_nonce(self.ENC_RAND, 0xA311, 2)
        self.assertNotEqual(n1, n2)

    def test_nonce_tail_selection(self):
        # derive_nonce takes the LAST 12 bytes of sha256x3(...)
        buf = struct.pack("<HH", 0xA311, 7) + self.ENC_RAND
        full = ucrypt._sha256x3(buf)
        expected_nonce = full[-12:]
        self.assertEqual(ucrypt.derive_nonce(self.ENC_RAND, 0xA311, 7), expected_nonce)


# ---------------------------------------------------------------------------
# GF(2^128) multiply (pure Python, no dependency)
# ---------------------------------------------------------------------------

class TestGfMul(unittest.TestCase):
    def test_multiply_by_zero(self):
        self.assertEqual(ucrypt._gf_mul(0xDEADBEEF, 0), 0)

    def test_multiply_by_one(self):
        # In GF(2^128) with MSB-first convention, the multiplicative identity
        # is 2^127 (the most significant bit set), not the integer 1.
        identity = 1 << 127
        x = 0xDEADBEEF
        self.assertEqual(ucrypt._gf_mul(x, identity), x)

    def test_commutativity(self):
        a = 0x66E94BD4EF8A2C3B884CFA59CA342B2E
        b = 0xB83B533708BF535D0AA6E52980D53B78
        self.assertEqual(ucrypt._gf_mul(a, b), ucrypt._gf_mul(b, a))

    def test_known_subkey(self):
        # GHASH subkey derivation: H = AES(K, 0^128). We test indirectly
        # by checking _gf_mul(H, H) is deterministic.
        H = 0x66E94BD4EF8A2C3B884CFA59CA342B2E
        r1 = ucrypt._gf_mul(H, H)
        r2 = ucrypt._gf_mul(H, H)
        self.assertEqual(r1, r2)


# ---------------------------------------------------------------------------
# _pad16
# ---------------------------------------------------------------------------

class TestPad16(unittest.TestCase):
    def test_already_aligned(self):
        self.assertEqual(ucrypt._pad16(b"a" * 16), b"a" * 16)

    def test_empty(self):
        self.assertEqual(ucrypt._pad16(b""), b"")

    def test_short(self):
        result = ucrypt._pad16(b"abc")
        self.assertEqual(len(result), 16)
        self.assertTrue(result.startswith(b"abc"))
        self.assertEqual(result[3:], b"\x00" * 13)

    def test_17_bytes(self):
        result = ucrypt._pad16(b"a" * 17)
        self.assertEqual(len(result), 32)


# ---------------------------------------------------------------------------
# AES-128-GCM encrypt / decrypt round-trips
# ---------------------------------------------------------------------------

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography package required")
class TestAesGcmRoundTrip(unittest.TestCase):
    KEY   = bytes(range(16))           # 0x00..0x0f
    NONCE = bytes(range(12))           # 0x00..0x0b
    AAD   = b"\x01\x02"

    def test_empty_plaintext(self):
        ct_tag = ucrypt.aes_gcm_encrypt(self.KEY, self.NONCE, b"", self.AAD)
        # Only tag (16 bytes)
        self.assertEqual(len(ct_tag), 16)
        pt = ucrypt.aes_gcm_decrypt(self.KEY, self.NONCE, ct_tag, self.AAD)
        self.assertEqual(pt, b"")

    def test_short_plaintext(self):
        pt_in = b"hello world"
        ct_tag = ucrypt.aes_gcm_encrypt(self.KEY, self.NONCE, pt_in, self.AAD)
        pt_out = ucrypt.aes_gcm_decrypt(self.KEY, self.NONCE, ct_tag, self.AAD)
        self.assertEqual(pt_out, pt_in)

    def test_exactly_16_bytes(self):
        pt_in = b"A" * 16
        ct_tag = ucrypt.aes_gcm_encrypt(self.KEY, self.NONCE, pt_in, self.AAD)
        pt_out = ucrypt.aes_gcm_decrypt(self.KEY, self.NONCE, ct_tag, self.AAD)
        self.assertEqual(pt_out, pt_in)

    def test_binary_payload(self):
        pt_in = bytes(range(256))
        ct_tag = ucrypt.aes_gcm_encrypt(self.KEY, self.NONCE, pt_in, self.AAD)
        pt_out = ucrypt.aes_gcm_decrypt(self.KEY, self.NONCE, ct_tag, self.AAD)
        self.assertEqual(pt_out, pt_in)

    def test_output_length(self):
        pt_in = b"x" * 37
        ct_tag = ucrypt.aes_gcm_encrypt(self.KEY, self.NONCE, pt_in, self.AAD)
        self.assertEqual(len(ct_tag), len(pt_in) + 16)

    def test_ciphertext_differs_from_plaintext(self):
        pt_in = b"sensitive data!!"
        ct_tag = ucrypt.aes_gcm_encrypt(self.KEY, self.NONCE, pt_in, self.AAD)
        self.assertNotEqual(ct_tag[:16], pt_in)

    def test_wrong_key_raises(self):
        pt_in = b"test"
        ct_tag = ucrypt.aes_gcm_encrypt(self.KEY, self.NONCE, pt_in, self.AAD)
        wrong_key = bytes([k ^ 0xFF for k in self.KEY])
        with self.assertRaises(ValueError):
            ucrypt.aes_gcm_decrypt(wrong_key, self.NONCE, ct_tag, self.AAD)

    def test_wrong_aad_raises(self):
        pt_in = b"test"
        ct_tag = ucrypt.aes_gcm_encrypt(self.KEY, self.NONCE, pt_in, self.AAD)
        with self.assertRaises(ValueError):
            ucrypt.aes_gcm_decrypt(self.KEY, self.NONCE, ct_tag, b"\xff\xff")

    def test_tampered_ciphertext_raises(self):
        pt_in = b"test data"
        ct_tag = bytearray(ucrypt.aes_gcm_encrypt(self.KEY, self.NONCE, pt_in, self.AAD))
        ct_tag[0] ^= 0x01   # flip one bit in ciphertext
        with self.assertRaises(ValueError):
            ucrypt.aes_gcm_decrypt(self.KEY, self.NONCE, bytes(ct_tag), self.AAD)

    def test_too_short_input_raises(self):
        with self.assertRaises(ValueError):
            ucrypt.aes_gcm_decrypt(self.KEY, self.NONCE, b"\x00" * 10, self.AAD)


# ---------------------------------------------------------------------------
# crypt_data high-level API
# ---------------------------------------------------------------------------

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography package required")
class TestCryptData(unittest.TestCase):
    ENC_RAND = b"abcdefghijklmnop"  # 16 bytes

    def test_encrypt_decrypt_roundtrip(self):
        plaintext = b"power limit data"
        ciphertext = ucrypt.crypt_data(True,  self.ENC_RAND, 0xA311, 1, plaintext)
        recovered  = ucrypt.crypt_data(False, self.ENC_RAND, 0xA311, 1, ciphertext)
        self.assertEqual(recovered, plaintext)

    def test_encrypt_changes_data(self):
        plaintext = b"hello world"
        ciphertext = ucrypt.crypt_data(True, self.ENC_RAND, 0xA311, 1, plaintext)
        self.assertNotEqual(ciphertext[:len(plaintext)], plaintext)

    def test_different_seq_different_output(self):
        plaintext = b"same"
        c1 = ucrypt.crypt_data(True, self.ENC_RAND, 0xA311, 1, plaintext)
        c2 = ucrypt.crypt_data(True, self.ENC_RAND, 0xA311, 2, plaintext)
        self.assertNotEqual(c1, c2)

    def test_different_tag_different_output(self):
        plaintext = b"same"
        c1 = ucrypt.crypt_data(True, self.ENC_RAND, 0xA311, 1, plaintext)
        c2 = ucrypt.crypt_data(True, self.ENC_RAND, 0xA303, 1, plaintext)
        self.assertNotEqual(c1, c2)


if __name__ == "__main__":
    unittest.main()
