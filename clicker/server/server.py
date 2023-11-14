import asyncio
import logging
import socket

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from clicker.common.exceptions import MalformedKeyRequest
from clicker.server.manager import ClientManager


class SusServer:
    def __init__(self, ip: str, port: int, psks: bytes):
        self.ip = ip
        self.port = port
        self.logger = logging.getLogger("gatekeeper")

        self.psks = X25519PrivateKey.from_private_bytes(psks)
        self.ppks = self.psks.public_key()

        with open("server.pub", "w") as f:
            f.write(self.ppks.public_bytes(Encoding.Raw, PublicFormat.Raw).hex())

        self.shutdown = asyncio.Event()
        self.manager = ClientManager(self.psks, self.ppks)

    async def start(self):
        self.logger.info("Starting server")
        self.logger.info(f"public key: {self.ppks.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}")

        # create udp socket listener
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.setblocking(False)
        server.settimeout(1)
        server.bind((self.ip, self.port))

        self.logger.info(f"Listening on {self.ip}:{self.port}")
        counter = 0
        while not self.shutdown.is_set():

            counter = (counter + 1) % 10
            if counter == 0:
                await self.manager.clean()
                continue
            await asyncio.sleep(0.5)  # let other tasks run TODO: remove this

            # listen for incoming packets
            try:
                data, addr = server.recvfrom(40)
                self.logger.info(f"{addr} - {data.hex()}")
            except TimeoutError:
                #
                continue

            # handle incoming packets
            try:
                res = await self.manager.handle_client(data)
                server.sendto(res, addr)
            except MalformedKeyRequest as e:
                self.logger.warning(f"{addr} - {e}")
                continue

        self.manager.stop_all()
        self.logger.info("Server stopped")

    async def stop(self):
        self.logger.warning("Shutting down")
        self.shutdown.set()
        self.manager.stop_all()