from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from clicker import SusClient


def main():
    with open("server.pub", "r") as f:
        ppks_bytes = bytes.fromhex(key := f.read())
        print(f"Using public key {key}")
    ppks = X25519PublicKey.from_public_bytes(ppks_bytes)
    client = SusClient("localhost", 42069, ppks, b"app_id")
    client.connection_made(True)
    client.send(b"hello world")
    client.send(b"goodbye world")
    client.close()
    exit(0)


if __name__ == "__main__":
    main()
