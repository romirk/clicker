from typing import Awaitable, Callable


class ClientHandler:
    def __init__(self, addr: tuple[str, int],
                 send_message: Callable[[bytes], Awaitable[None]]):
        self.addr = addr
        self.send = send_message

    def handle_message(self, msg_id: int, msg: bytes):
        pass
