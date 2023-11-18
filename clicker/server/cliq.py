import asyncio
import logging

from clicker import SusServer

from server.handler import ClientHandler

def parse_message(msg: bytes) -> Message:
    pass

class CliqServer:
    def __init__(self, key: str):
        self.server = SusServer(("0.0.0.0", 42069), key)
        self.clients: dict[tuple[str, int], ClientHandler] = {}
        self.logger = logging.getLogger("cliqserver")

    async def message_handler(self, addr: tuple[str, int], msg_id: int,
                              data: bytes):
        
        msg = parse_message(data)
        
        if addr in self.clients:
            self.clients[addr].handle_message(msg_id, msg)
            return

        async def _send(m: bytes): await self.send_message(addr, m)

        self.clients[addr] = ClientHandler(addr, _send)
        self.clients[addr].handle_message(msg_id, msg)

    async def send_message(self, addr: tuple[str, int], msg: bytes):
        await self.server.send(addr, msg)

    async def start(self):
        asyncio.create_task(self.server.start([self.message_handler]))
