from typing import Awaitable, Callable


class CliqAgent:

    def __init__(self, send: Callable[[bytes], Awaitable]) -> None:
        self.send = send
    
    
