import asyncio
import logging

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from clicker.protocol import ClickerProtocol


class ClientManager:

    def __init__(self):
        self.logger = logging.getLogger("manager")
        self.clients: set[ClickerProtocol] = set()

    def add_client(self, client: ClickerProtocol):
        self.clients.add(client)
        self.logger.info(f"{client.addr} connected. {len(self.clients)} client(s) online.")

    def remove_client(self, client: ClickerProtocol):
        self.clients.remove(client)
        self.logger.info(f"{client.addr} disconnected. {len(self.clients)} client(s) online.")

    async def handle_client(self, data: bytes, addr: tuple[str, int], psks: X25519PrivateKey,
                            ppks: X25519PublicKey):
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: ClickerProtocol(psks, ppks, addr, data, lambda _: self.remove_client(protocol)),
            ("0.0.0.0", 0))
        self.add_client(protocol)
