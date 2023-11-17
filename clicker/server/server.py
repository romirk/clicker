import asyncio
import logging
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from clicker.common.util import Handler, Wallet, now
from clicker.server.protocol import OnePortProtocol


class SusServer:
    protocol: OnePortProtocol

    def __init__(self, addr: tuple[str, int], psks: str):
        self.addr = addr
        self.logger = logging.getLogger("gatekeeper")

        self.psks = X25519PrivateKey.from_private_bytes(bytes.fromhex(psks))
        self.ppks = self.psks.public_key()

        with open("server.pub", "w") as f:
            f.write(self.ppks.public_bytes(Encoding.Raw, PublicFormat.Raw).hex())

        self.shutdown = asyncio.Event()

    async def __garbage_collector(self):
        while not self.shutdown.is_set():
            try:
                await asyncio.sleep(10)
                for addr in list(self.protocol.clients.keys()):
                    if now() - self.protocol.clients[addr].last_seen > 30:
                        self.logger.info(f"Client {addr} timed out")
                        del self.protocol.clients[addr]
            except asyncio.CancelledError:
                self.logger.info("Garbage collector exiting...")
                return

    async def one_port(self, message_handlers: Iterable[Handler] = None):
        self.logger.info("Starting server")
        self.logger.info(f"public key: {self.ppks.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}")

        wallet = Wallet(ppks=self.ppks, psks=self.psks)

        _, self.protocol = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: OnePortProtocol(wallet, message_handlers if message_handlers else []),
            self.addr)

        gc_task = None
        try:
            gc_task = asyncio.create_task(self.__garbage_collector())
            await self.protocol.closed.wait()
        except asyncio.CancelledError:
            self.logger.info("Server stopped")
        finally:
            if gc_task:
                gc_task.cancel()
            self.protocol.transport.close()

    async def stop(self):
        self.logger.warning("Shutting down")
        self.shutdown.set()
