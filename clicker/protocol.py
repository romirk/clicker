import asyncio
import logging
from enum import Enum
from os import urandom
from typing import Callable

from blake3 import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import CipherContext, Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from clicker.globals import CLIENT_ENC_NONCE, SERVER_ENC_NONCE, CLIENT_MAC_NONCE, SERVER_MAC_NONCE
from clicker.util import trail_off


class ConnectionProtocolState(Enum):
    ERROR = -1
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

        self.logger = logging.getLogger(f"clicker{ClickerProtocol.counter:03d}")

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
        self.logger.info(f"allocated port to {self.addr}")

        self.state = ConnectionProtocolState.HANDSHAKE

    def datagram_received(self, data: bytes, addr: tuple[str, int]):

        match self.state:
            case ConnectionProtocolState.HANDSHAKE:
                self.token = blake3(self.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                                    self.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) + self.nc + self.ns).digest()
                client_token = data[8:40]

                self.logger.debug(f"token: {client_token.hex()}")

                if client_token != self.token:
                    self.logger.debug(f"ours : {self.token.hex()}")
                    self.logger.error("token mismatch!")

                    self.state = ConnectionProtocolState.ERROR
                    self.disconnect()
                    return
                self.logger.debug("token: OK")

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
                self.client_mac = Cipher(ChaCha20(self.shared_secret, b"\x00" * 8 + CLIENT_MAC_NONCE), None).encryptor()
                self.server_mac = Cipher(ChaCha20(self.shared_secret, b"\x00" * 8 + SERVER_MAC_NONCE), None).encryptor()

                self.state = ConnectionProtocolState.CONNECTED
                self.logger.debug("Handshake complete")

            case ConnectionProtocolState.CONNECTED:
                self.logger.info(f"{addr} {trail_off(data.hex())}")
                try:
                    poly1305.Poly1305.verify_tag(self.client_mac.update(b"\x00" * 32), data[:-16], data[-16:])
                except InvalidSignature:
                    self.logger.error("Invalid signature")

                    self.state = ConnectionProtocolState.ERROR
                    self.disconnect()
                    return
                p_id = int.from_bytes(data[:8], "little")
                message_bytes = self.client_enc.update(data[8:-16])
                message_length = int.from_bytes(message_bytes[:4], "little")
                message = message_bytes[4:]
                self.logger.info(f"Received {message_length} bytes from {addr}")

            case ConnectionProtocolState.ERROR:
                self.logger.error("Error state reached")
                self.disconnect()

    def disconnect(self):
        self.logger.warning("Disconnecting...")
        self.transport.close()

    def connection_lost(self, exc: Exception):
        self.logger.warning("Connection lost" + (f": {exc}" if exc else ""))
        self.on_close(exc)
