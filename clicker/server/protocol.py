import asyncio
import logging
from datetime import datetime
from typing import Callable

from blake3 import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, CipherContext
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from clicker.common.globals import CLIENT_ENC_NONCE, CLIENT_MAC_NONCE, SERVER_ENC_NONCE, SERVER_MAC_NONCE
from clicker.common.util import ConnectionProtocolState, Wallet, now, trail_off


class ClickerServerProtocol(asyncio.DatagramProtocol):
    transport: asyncio.DatagramTransport

    cl_enc: CipherContext
    sr_enc: CipherContext
    cl_mac: CipherContext
    sr_mac: CipherContext

    counter: int = 0

    def __init__(self, wallet: Wallet, on_close: Callable = lambda _: None):
        super().__init__()

        self.wallet = wallet
        self.on_close = on_close

        self.logger = logging.getLogger(f"clicker{ClickerServerProtocol.counter:03d}")

        self.state = ConnectionProtocolState.INITIAL
        self.last_seen = now()

        self.client_message_id = 0
        self.server_message_id = 0
        self.client_packet_id = 0
        self.server_packet_id = 0

        self.mtu_estimate = 1500

        ClickerServerProtocol.counter += 1

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport
        self.state = ConnectionProtocolState.HANDSHAKE

    def check_alive(self):
        if self.state in (ConnectionProtocolState.ERROR,
                          ConnectionProtocolState.DISCONNECTED) or datetime.now().timestamp() - self.last_seen > 5:
            self.disconnect()

    def __verify_and_decrypt(self, data: bytes) -> bytes | None:
        try:
            p_id = int.from_bytes(data[:8], "little")
            key = self.cl_mac.update(b"\x00" * 32)
            payload = data[8:-16]
            tag = data[-16:]
            poly1305.Poly1305.verify_tag(key, data[:8] + payload, tag)
        except InvalidSignature:
            self.logger.error("Invalid signature")
            return None

        # special case for first packet
        if p_id == 0:
            payload = payload[32:]
            self.logger.debug(f"--- {trail_off(payload.hex())}")

        message_bytes = self.cl_enc.update(payload)
        message_length = int.from_bytes(message_bytes[:4], "little")
        message = message_bytes[4:message_length + 4]
        self.logger.info(f"Received message {p_id} ({message_length} bytes)")
        self.last_seen = datetime.now().timestamp()
        self.client_packet_id = p_id
        return message

    def __encrypt_and_tag(self, data: bytes) -> bytes:
        message_bytes = len(data).to_bytes(4, "little") + data
        packet_length = self.mtu_estimate - 24
        padded_message_bytes = message_bytes + b"\x00" * (
                packet_length - ((len(message_bytes) + 0) % packet_length))

        ciphertext = self.sr_enc.update(padded_message_bytes)
        self.logger.debug(f"--- {trail_off(ciphertext.hex())}")

        key = self.sr_mac.update(b"\x00" * 32)
        p_id = self.server_packet_id.to_bytes(8, "little")
        frame = p_id + ciphertext
        tag = poly1305.Poly1305.generate_tag(key, frame)
        self.server_packet_id += 1
        return frame + tag

    def __key_exchange(self):
        wallet = self.wallet
        eces = wallet.esks.exchange(wallet.epkc)
        ecps = wallet.psks.exchange(wallet.epkc)
        wallet.shared_secret = blake3(
            eces + ecps + wallet.nc + wallet.ns +
            wallet.ppks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw)).digest()
        self.logger.debug(f"shared_secret: {wallet.shared_secret.hex()}")
        # noinspection DuplicatedCode
        self.cl_enc = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + CLIENT_ENC_NONCE), None).decryptor()
        self.sr_enc = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + SERVER_ENC_NONCE), None).encryptor()
        self.cl_mac = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + CLIENT_MAC_NONCE), None).decryptor()
        self.sr_mac = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + SERVER_MAC_NONCE), None).encryptor()

    def datagram_received(self, data: bytes, addr: tuple[str, int]):

        match self.state:
            case ConnectionProtocolState.HANDSHAKE:
                if len(data) < 40:
                    self.logger.error("Invalid handshake packet")
                    self.state = ConnectionProtocolState.ERROR
                    self.disconnect()
                    return

                wallet = self.wallet
                wallet.token = blake3(wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                                      wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                                      wallet.nc + wallet.ns).digest()
                client_token = data[8:40]

                self.logger.debug(f"token: {client_token.hex()}")

                if client_token != wallet.token:
                    self.logger.debug(f"ours : {self.wallet.token.hex()}")
                    self.logger.error("token mismatch!")

                    self.state = ConnectionProtocolState.ERROR
                    self.disconnect()
                    return
                self.logger.debug("token: OK")

                self.__key_exchange()

                self.state = ConnectionProtocolState.CONNECTED
                self.logger.debug("Handshake complete")

                message = self.__verify_and_decrypt(data)
                if message is None:
                    self.state = ConnectionProtocolState.ERROR
                    self.disconnect()
                    return

                self.logger.info(f"protocol: {message.decode('utf-8')}")

            case ConnectionProtocolState.CONNECTED:
                message = self.__verify_and_decrypt(data)
                self.logger.info(f"{addr[0]}:{addr[1]} >>> "
                                 f"{trail_off(message.decode('utf-8')) if message else None}")

                # for now, just echo back
                if message:
                    self.transport.sendto(self.__encrypt_and_tag(message), addr)

        self.last_seen = now()

    def disconnect(self):
        self.logger.warning("Disconnecting...")
        self.transport.close()

    def connection_lost(self, exc: Exception):
        self.logger.warning("Connection lost" + (f": {exc}" if exc else ""))
        self.on_close(exc)
