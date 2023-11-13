import asyncio
import logging
import socket
from enum import Enum
from os import urandom

from blake3 import blake3
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, CipherContext
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from clicker.globals import CLIENT_ENC_NONCE, SERVER_ENC_NONCE, CLIENT_MAC_NONCE, SERVER_MAC_NONCE


class ConnectionProtocolState(Enum):
    HANDSHAKE = 1
    CONNECTED = 2
    DISCONNECTED = 3


class ConnectionProtocol(asyncio.DatagramProtocol):
    esks: X25519PrivateKey
    epks: X25519PublicKey
    ns: bytes

    epkc: X25519PublicKey
    nc: bytes

    transport: asyncio.DatagramTransport

    token: bytes
    shared_secret: bytes

    client_enc: CipherContext
    server_enc: CipherContext
    client_mac: CipherContext
    server_mac: CipherContext

    def __init__(self, psks: X25519PrivateKey, ppks: X25519PublicKey, addr: tuple[str, int], data: bytes):
        super().__init__()
        self.psks = psks
        self.ppks = ppks
        self.logger = logging.getLogger("sus_server")
        self.logger.info("New connection")
        self.shutdown = asyncio.Event()

        self.esks = X25519PrivateKey.generate()
        self.epks = self.esks.public_key()

        self.ns = urandom(8)

        self.epkc = X25519PublicKey.from_public_bytes(data[:32])
        self.nc = data[32:]

        self.transport.sendto(self.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) + self.ns, addr)

        self.state = ConnectionProtocolState.HANDSHAKE


    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        self.logger.info(f"Received {data} from {addr}")

        match self.state:
            case ConnectionProtocolState.HANDSHAKE:
                self.token = blake3(self.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                                    self.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) + self.nc + self.ns).digest()
                client_token = data[8:40]
                if client_token != self.token:
                    self.logger.warning("Client token mismatch")
                    self.shutdown.set()
                    return

                eces = self.esks.exchange(self.epkc)
                ecps = self.psks.exchange(self.epkc)

                self.shared_secret = blake3(
                    eces + ecps + self.nc + self.ns +
                    self.ppks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                    self.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                    self.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw)).digest()

                # noinspection DuplicatedCode
                self.client_enc = Cipher(ChaCha20(self.shared_secret, b"\x00" * 8 + CLIENT_ENC_NONCE), None).decryptor()
                self.server_enc = Cipher(ChaCha20(self.shared_secret, b"\x00" * 8 + SERVER_ENC_NONCE), None).encryptor()
                self.client_mac = Cipher(ChaCha20(self.shared_secret, b"\x00" * 8 + CLIENT_MAC_NONCE), None).decryptor()
                self.server_mac = Cipher(ChaCha20(self.shared_secret, b"\x00" * 8 + SERVER_MAC_NONCE), None).encryptor()

                self.state = ConnectionProtocolState.CONNECTED


async def handle_client(sock: socket.socket, data: bytes, addr: tuple[str, int], psks: X25519PrivateKey, ppks: X25519PublicKey):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(lambda: ConnectionProtocol(psks, ppks, addr, data), sock=sock)


class SusServer:
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        self.psks = X25519PrivateKey.generate()
        self.ppks = self.psks.public_key()

        self.logger = logging.getLogger("sus_server")
        self.shutdown = asyncio.Event()

    async def start(self):
        self.logger.info("Starting server")

        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind((self.ip, self.port))
        while not self.shutdown.is_set():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((self.ip, 0))
            data, addr = sock.recvfrom(40)
            await handle_client(sock, data, addr, self.psks, self.ppks)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    server = SusServer("localhost", 22023, )
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        server.shutdown.set()
