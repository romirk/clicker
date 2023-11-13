import asyncio
import logging

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from clicker.protocol import ClickerProtocol


class ClientManager:

    def __init__(self):
        self.logger = logging.getLogger("manager")
        self.clients: set[ClickerProtocol] = set()

    def add_client(self, client: ClickerProtocol):
        self.logger.info(f"New client {client.addr}")
        self.clients.add(client)

    def remove_client(self, client: ClickerProtocol):
        self.logger.info(f"Client {client.addr} disconnected")
        self.clients.remove(client)

    async def handle_client(self, data: bytes, addr: tuple[str, int], psks: X25519PrivateKey,
                            ppks: X25519PublicKey):
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: ClickerProtocol(psks, ppks, addr, data, lambda _: self.remove_client(protocol)),
            ("0.0.0.0", 0))
        self.add_client(protocol)
