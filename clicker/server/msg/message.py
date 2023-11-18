from abc import ABC


class Message(ABC):
    def __init__(self):
        pass
    
    def to_bytes(self) -> bytes:
        pass
