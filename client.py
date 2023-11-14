import argparse

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from clicker import SusClient
from clicker.util import logger_config


def main(host: str):
    logger_config()
    with open("server.pub", "r") as f:
        ppks_bytes = bytes.fromhex(key := f.read())
        print(f"Using public key {key}")
    ppks = X25519PublicKey.from_public_bytes(ppks_bytes)
    client = SusClient(host, 42069, ppks, b"cliq")
    client.connection_made(True)
    client.send(b"hello world")
    client.send(b"goodbye world")
    client.close()
    exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clicker client")
    parser.add_argument("host", type=str, default="localhost", help="host")
    args = parser.parse_args()
    main(args.host)
