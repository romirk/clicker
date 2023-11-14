import argparse
import asyncio

from clicker import SusServer
from clicker.util import logger_config


def main(key_file: str):
    logger_config()
    with open(key_file, "r") as f:
        psks_bytes = bytes.fromhex(key := f.read())
    server = SusServer("0.0.0.0", 42069, psks_bytes)

    loop = asyncio.get_event_loop()

    try:
        loop.run_until_complete(server.start())
    except KeyboardInterrupt:
        loop.run_until_complete(server.stop())
    finally:
        loop.close()
    print("done")
    exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clicker server")
    parser.add_argument("key", type=str, default="server.key", help="key file")
    args = parser.parse_args()
    main(args.key)
