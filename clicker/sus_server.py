import asyncio
import logging
import socket

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from clicker.manager import ClientManager


class SusServer:
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        self.psks = X25519PrivateKey.generate()
        self.ppks = self.psks.public_key()

        self.logger = logging.getLogger("gatekeeper")
        self.shutdown = asyncio.Event()

    async def start(self):
        self.logger.info("Starting server")
        self.logger.info(f"public key: {self.ppks.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}")

        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.setblocking(False)
        server.settimeout(1)
        server.bind((self.ip, self.port))
        handler = ClientManager()

        self.logger.info(f"Listening on {self.ip}:{self.port}")
        try:
            while not self.shutdown.is_set():
                try:
                    data, addr = server.recvfrom(40)
                except socket.timeout:
                    continue
                self.logger.info(f"Received {data.hex()} from {addr}")
                await handler.handle_client(data, addr, self.psks, self.ppks)
        except asyncio.CancelledError:
            self.logger.info("Keyboard interrupt")
        finally:
            server.close()
            self.logger.info("Server stopped")

        self.logger.info("Shutting down")

    async def stop(self):
        self.shutdown.set()
