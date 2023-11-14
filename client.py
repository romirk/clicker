import argparse

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from clicker import SusClient
from clicker.common.util import logger_config


def main(host: str, port: int, key: str):
    logger_config()
    with open(key, "r") as f:
        ppks_bytes = bytes.fromhex(key := f.read())
        print(f"Using public key {key}")
    ppks = X25519PublicKey.from_public_bytes(ppks_bytes)
    client = SusClient(host, port, ppks, b"cliq")
    client.connection_made(True)
    client.send(b"hello world")
    client.send(b"goodbye world")
    client.close()
    exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clicker client")
    parser.add_argument("--host", type=str, default="localhost", help="host")
    parser.add_argument("--port", type=int, default=42069, help="port")
    parser.add_argument("--key", type=str, default="server.pub", help="key file")
    args = parser.parse_args()
    main(args.host, args.port, args.key)
