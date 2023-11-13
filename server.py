from clicker import SusServer
from logging import basicConfig, DEBUG
import asyncio

if __name__ == "__main__":
    basicConfig(level=DEBUG)
    server = SusServer("0.0.0.0", 42069)

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        server.shutdown.set()
    exit(0)

