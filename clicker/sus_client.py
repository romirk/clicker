import socket
from os import urandom

from blake3 import blake3
from cryptography.hazmat.primitives import poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, CipherContext
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from clicker.globals import CLIENT_ENC_NONCE, SERVER_ENC_NONCE, CLIENT_MAC_NONCE, SERVER_MAC_NONCE


class SusClient:
    token: bytes
    shared_secret: bytes

    client_enc: CipherContext
    server_enc: CipherContext
    client_mac: CipherContext
    server_mac: CipherContext

    conn_addr: tuple[str, int]

    def __init__(self, host: str, port: int, ppks: X25519PublicKey, app_id: bytes):
        self.host = host
        self.port = port
        self.ppks = ppks
        self.app_id = app_id

        self.client_message_id = 0
        self.server_message_id = 0
        self.client_packet_id = 0
        self.server_packet_id = 0

        self.stream = bytearray()

        # udp socket
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setblocking(False)
        udp.settimeout(5)
        self.__udp = udp

        self.mtu_estimate = 1024  # TODO: implement mtu estimation

    def __del__(self):
        self.close()

    def connection_made(self, auto_complete=False):
        # 1. Generate a new ephemeral key pair (eskc, epkc)
        eskc = X25519PrivateKey.generate()
        epkc = eskc.public_key()

        # 2. generate nonce (nc) [8 bytes]
        nc = urandom(8)

        # 3. send (epkc, nc) to server
        self.__udp.sendto(epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) + nc, (self.host, self.port))
        print("sent keys")

        # 4. receive (epks, ns) from server
        epks_ns, self.conn_addr = self.__udp.recvfrom(40)
        print("received keys, starting handshake on port", self.conn_addr[1])

        epks = X25519PublicKey.from_public_bytes(epks_ns[:32])
        ns = epks_ns[32:]

        # 5. compute ecps = X25519(eskc, ppks)
        ecps = eskc.exchange(self.ppks)
        eces = eskc.exchange(epks)

        # 6. compute key = H(eces, ecps, nc, ns, ppks, epks, epkc)
        self.shared_secret = blake3(
            eces + ecps + nc + ns + self.ppks.public_bytes(Encoding.Raw, PublicFormat.Raw) + epks.public_bytes(
                Encoding.Raw, PublicFormat.Raw) + epkc.public_bytes(Encoding.Raw, PublicFormat.Raw)).digest()

        self.client_enc = Cipher(ChaCha20(self.shared_secret, b"\x00" * 8 + CLIENT_ENC_NONCE), None).encryptor()
        self.server_enc = Cipher(ChaCha20(self.shared_secret, b"\x00" * 8 + SERVER_ENC_NONCE), None).decryptor()
        self.client_mac = Cipher(ChaCha20(self.shared_secret, b"\x00" * 8 + CLIENT_MAC_NONCE), None).encryptor()
        self.server_mac = Cipher(ChaCha20(self.shared_secret, b"\x00" * 8 + SERVER_MAC_NONCE), None).decryptor()

        # 7. compute token = H(epkc, epks, nc, ns)
        self.token = blake3(epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                            epks.public_bytes(Encoding.Raw, PublicFormat.Raw) + nc + ns).digest()

        if auto_complete:
            self.complete_handshake_and_send(self.app_id)

    def split_message(self, data: bytes) -> list[bytes]:
        packet_length = self.mtu_estimate - 24
        return [data[i:i + packet_length] for i in range(0, len(data), packet_length)]

    def complete_handshake_and_send(self, data: bytes):
        message_bytes = self.token + self.encrypt(data, len(self.token))
        payloads = self.split_message(message_bytes)

        for payload in payloads:
            p = poly1305.Poly1305(self.client_mac.update(b"\x00" * 32))
            frame = self.client_packet_id.to_bytes(8, "little") + payload
            p.update(frame)
            frame += p.finalize()
            self.__udp.sendto(frame, self.conn_addr)
            self.client_packet_id += 1

        print("handshake complete")

    def encrypt(self, data: bytes, len_assoc_data=0) -> bytes:
        message_bytes = len(data).to_bytes(4, "little") + data
        packet_length = self.mtu_estimate - 24
        padded_message_bytes = message_bytes + b"\x00" * (
                packet_length - ((len(message_bytes) + len_assoc_data) % packet_length))

        return self.client_enc.update(padded_message_bytes)

    def send(self, data: bytes):
        message_bytes = self.encrypt(data)
        payloads = self.split_message(message_bytes)

        print(f"Sending {len(message_bytes)} bytes as {len(payloads)} packet(s)")
        for payload in payloads:
            p = poly1305.Poly1305(self.client_mac.update(b"\x00" * 32))
            frame = self.client_packet_id.to_bytes(8, "little") + payload
            p.update(frame)
            frame += p.finalize()
            self.__udp.sendto(frame, self.conn_addr)
            self.client_packet_id += 1

    def close(self):
        self.__udp.close()
