from dataclasses import dataclass
from enum import Enum
from logging import DEBUG, basicConfig
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey


def trail_off(msg: str, length: int = 40):
    if len(msg) > length:
        msg = msg[:length - 3] + "..."
    return msg


def logger_config():
    basicConfig(level=DEBUG, format="%(asctime)s | %(name)s - %(levelname)8s : %(message)s")


@dataclass
class Wallet:
    psks: Optional[X25519PrivateKey]
    ppks: X25519PublicKey

    esks: Optional[X25519PrivateKey]
    epks: X25519PublicKey
    ns: Optional[bytes]

    eskc: Optional[X25519PrivateKey]
    epkc: X25519PublicKey
    nc: Optional[bytes]

    token: Optional[bytes]
    shared_secret: Optional[bytes]


class ConnectionProtocolState(Enum):
    ERROR = -1
    INITIAL = 0
    HANDSHAKE = 1
    CONNECTED = 2
    DISCONNECTED = 3
