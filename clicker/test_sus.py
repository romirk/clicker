from unittest import TestCase

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20

from clicker.sus import CLIENT_ENC_NONCE, SusClient


def decrypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = Cipher(ChaCha20(key, b"\x00" * 8 + nonce), None)
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


class TestSusClient(TestCase):

    def test_split_message(self):
        self.fail()

    def test_encrypt(self):
        data = b"Hello, World!"
        client = SusClient("localhost", 5000, X25519PrivateKey.generate().public_key(), b"test")
        client.handshake()
        encrypted = client.encrypt(data)
        self.assertEqual(data, decrypt(encrypted, client.shared_secret, CLIENT_ENC_NONCE))
