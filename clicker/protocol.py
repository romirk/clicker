import asyncio
import logging
from enum import Enum
from os import urandom
from typing import Callable

from blake3 import blake3
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import CipherContext, Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from clicker.globals import CLIENT_ENC_NONCE, SERVER_ENC_NONCE, CLIENT_MAC_NONCE, SERVER_MAC_NONCE
from clicker.util import trail_off


class ConnectionProtocolState(Enum):
    INITIAL = 0
    HANDSHAKE = 1
    CONNECTED = 2
    DISCONNECTED = 3


class ClickerProtocol(asyncio.DatagramProtocol):
    esks: X25519PrivateKey
    epks: X25519PublicKey
    ns: bytes

    epkc: X25519PublicKey
    nc: bytes

    transport: asyncio.DatagramTransport

    token: bytes
    shared_secret: bytes

    client_enc: CipherContext
    server_enc: CipherContext
    client_mac: CipherContext
    server_mac: CipherContext

    counter: int = 0

    def __init__(self, psks: X25519PrivateKey, ppks: X25519PublicKey, addr: tuple[str, int], data: bytes,
                 on_close: Callable = lambda _: None):
        super().__init__()
        self.psks = psks
        self.ppks = ppks
        self.addr = addr
        self.on_close = on_close

        self.logger = logging.getLogger(f"clicker{ClickerProtocol.counter}")
        self.logger.info("New connection")
        self.shutdown = asyncio.Event()

        self.esks = X25519PrivateKey.generate()
        self.epks = self.esks.public_key()

        self.ns = urandom(8)

        self.epkc = X25519PublicKey.from_public_bytes(data[:32])
        self.nc = data[32:]
        self.state = ConnectionProtocolState.INITIAL
        ClickerProtocol.counter += 1

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport
        self.transport.sendto(self.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) + self.ns, self.addr)
        self.logger.info(f"Connection made to {self.addr}")

        self.state = ConnectionProtocolState.HANDSHAKE

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        self.logger.info(f"{addr}: {trail_off(data.hex())}")

        match self.state:
            case ConnectionProtocolState.HANDSHAKE:
                self.token = blake3(self.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                                    self.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) + self.nc + self.ns).digest()
                client_token = data[8:40]
                if client_token != self.token:
                    self.logger.warning("Client token mismatch")
                    self.shutdown.set()
                    return

                eces = self.esks.exchange(self.epkc)
                ecps = self.psks.exchange(self.epkc)

                self.shared_secret = blake3(
                    eces + ecps + self.nc + self.ns +
                    self.ppks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                    self.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                    self.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw)).digest()

                # noinspection DuplicatedCode
                self.client_enc = Cipher(ChaCha20(self.shared_secret, b"\x00" * 8 + CLIENT_ENC_NONCE), None).decryptor()
                self.server_enc = Cipher(ChaCha20(self.shared_secret, b"\x00" * 8 + SERVER_ENC_NONCE), None).encryptor()
                self.client_mac = Cipher(ChaCha20(self.shared_secret, b"\x00" * 8 + CLIENT_MAC_NONCE), None).decryptor()
                self.server_mac = Cipher(ChaCha20(self.shared_secret, b"\x00" * 8 + SERVER_MAC_NONCE), None).encryptor()

                self.state = ConnectionProtocolState.CONNECTED
                self.logger.info("Handshake complete")
            case ConnectionProtocolState.CONNECTED:
                self.logger.info(f"{addr}: {trail_off(data.hex())}")

    def connection_lost(self, exc: Exception):
        self.logger.info("Connection lost")
        self.shutdown.set()

        self.on_close(exc)
