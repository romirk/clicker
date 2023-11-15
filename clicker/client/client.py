import asyncio
import logging
import socket
from os import urandom
from typing import Iterable

from blake3 import blake3
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from clicker.client.protocol import ClickerClientProtocol
from clicker.common.util import ConnectionProtocolState, Handler, Wallet


class SusClient:
    protocol: ClickerClientProtocol

    def __init__(self, host: str, port: int, ppks: X25519PublicKey, protocol_id: bytes):
        self.server_addr = (host, port)
        self.ppks = ppks
        self.protocol_id = protocol_id

        self.logger = logging.getLogger(f"susclicker")

    def __del__(self):
        self.disconnect()

    @property
    def connected(self):
        return hasattr(self, "protocol") and self.protocol.state == ConnectionProtocolState.CONNECTED

    def start(self, handlers: Iterable[Handler] = None):
        try:
            asyncio.get_event_loop().run_until_complete(self.connect())
        except KeyboardInterrupt:
            self.logger.info("interrupted")
        # finally:
        #     self.disconnect()
        for handler in handlers or []:
            self.protocol.add_message_handler(handler)

    def __key_exchange(self, epks_ns_port: bytes, wallet: Wallet):

        # 4. receive (epks, ns, port) from server
        wallet.epks = X25519PublicKey.from_public_bytes(epks_ns_port[:32])
        wallet.ns = epks_ns_port[32:40]
        port = int.from_bytes(epks_ns_port[40:], "little", signed=False)
        self.conn_addr = (self.server_addr[0], port)
        self.logger.info("received keys, starting handshake on port %s", port)
        # 5. compute ecps = X25519(eskc, ppks)
        ecps = wallet.eskc.exchange(wallet.ppks)
        eces = wallet.eskc.exchange(wallet.epks)
        # 6. compute key = H(eces, ecps, nc, ns, ppks, epks, epkc)
        wallet.shared_secret = blake3(
            eces + ecps + wallet.nc + wallet.ns +
            wallet.ppks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw)).digest()
        self.logger.info("shared secret: %s", wallet.shared_secret.hex())

        # 7. compute token = H(epkc, epks, nc, ns)
        wallet.token = blake3(wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                              wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                              wallet.nc + wallet.ns).digest()
        return port, wallet

    async def connect(self):
        self.logger.info(f"connecting to server ({self.server_addr[0]}:{self.server_addr[1]})")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(self.server_addr)

        eskc = X25519PrivateKey.generate()
        epkc = eskc.public_key()
        nc = urandom(8)
        wallet = Wallet(None, self.ppks, None, None, None, eskc, epkc, nc, None, None)

        try:
            sock.send(wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) + wallet.nc)
            data = sock.recv(42)
        except ConnectionRefusedError:
            self.logger.error("Connection refused")
            return
        except TimeoutError:
            self.logger.error("Connection timed out")
            return

        port, wallet = self.__key_exchange(data, wallet)

        self.logger.info("received keys, starting handshake on port %s", port)

        _, self.protocol = await asyncio.get_event_loop().create_datagram_endpoint(
            lambda: ClickerClientProtocol(wallet, self.protocol_id),
            remote_addr=(self.server_addr[0], port)
        )
        await self.protocol.handshake_event.wait()

    def send(self, data: bytes):
        if not self.protocol:
            self.logger.warning("not connected to server")
            return
        self.protocol.send(data)

    def disconnect(self):
        if not hasattr(self, "protocol"):
            self.logger.warning("not connected to server")
            return
        self.protocol.disconnect()
        self.logger.info(f"disconnected from server ({self.server_addr[0]}:{self.server_addr[1]})")

    def keep_alive(self):
        if not hasattr(self, "protocol"):
            self.logger.warning("not connected to server")
            return
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(self.protocol.diconnection_event.wait())
        except KeyboardInterrupt:
            self.logger.info("exiting...")
