from clicker import SusClient
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

def main():
    ppks_bytes = bytes.fromhex("ede93541b9bf0e29bc03f88fd2257525d225af16842bcd92931bfd77d664066e")
    ppks = X25519PublicKey.from_public_bytes(ppks_bytes)
    client = SusClient("localhost", 42069, ppks, b"app_id")
    client.connection_made(True)
    exit(0)
if __name__ == "__main__":
    main()
