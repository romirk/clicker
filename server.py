import asyncio
from logging import basicConfig, DEBUG

from clicker import SusServer

if __name__ == "__main__":
    basicConfig(level=DEBUG)
    server = SusServer("0.0.0.0", 42069)

    loop = asyncio.get_event_loop()

    try:
        loop.run_until_complete(server.start())
    except KeyboardInterrupt:
        print("Shutting down")
        loop.run_until_complete(server.stop())
    exit(0)
