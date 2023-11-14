import asyncio
import logging
from os import urandom

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from clicker.common.exceptions import MalformedKeyRequest
from clicker.server.protocol import ClickerServerProtocol
from clicker.common.util import ConnectionProtocolState, Wallet


class ClientManager:

    def __init__(self, psks: X25519PrivateKey, ppks: X25519PublicKey):
        self.logger = logging.getLogger("susmanager")
        self.psks = psks
        self.ppks = ppks
        self.clients: set[ClickerServerProtocol] = set()

    def add_client(self, client: ClickerServerProtocol):
        self.clients.add(client)
        self.logger.info(f"{len(self.clients)} client(s) online.")

    def remove_client(self, client: ClickerServerProtocol):
        self.clients.remove(client)
        self.logger.info(f"{len(self.clients)} client(s) online.")

    async def handle_client(self, data: bytes) -> bytes:
        """
        Handle a key request from a client. Allocates a port for the client to connect to.

        :param data: key request data
        :param psks:
        :param ppks:
        :return:
        """

        if len(data) != 40:
            raise MalformedKeyRequest("Invalid key request length")

        # TODO: check if client is already connected

        # generate wallet
        esks = X25519PrivateKey.generate()
        epks = esks.public_key()
        ns = urandom(8)
        epkc = X25519PublicKey.from_public_bytes(data[:32])
        nc = data[32:]

        wallet = Wallet(self.psks, self.ppks, esks, epks, ns, None, epkc, nc, None, None)

        # assign port to client
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: ClickerServerProtocol(wallet, lambda _: self.remove_client(protocol)),
            ("0.0.0.0", 0))
        self.add_client(protocol)

        new_port: int = transport.get_extra_info("sockname")[1]
        self.logger.info(f"Opened port {new_port}")
        return (wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                wallet.ns + new_port.to_bytes(2, "little", signed=False))

    async def clean(self):
        if not self.clients:
            return
        self.logger.info("Cleaning up dead clients...")
        for client in self.clients:
            if client.state in (ConnectionProtocolState.DISCONNECTED, ConnectionProtocolState.ERROR):
                self.remove_client(client)
            else:
                client.check_alive()

    def stop_all(self):
        self.logger.info("Stopping all clients...")
        for client in self.clients:
            client.disconnect()
        self.logger.info("Stopped all clients.")
