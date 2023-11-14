import asyncio
import os

from clicker import SusServer
from clicker.util import logger_config

if __name__ == "__main__":
    logger_config()
    server = SusServer("0.0.0.0", 42069, os.environ.get("CLICKER_SECRET_KEY", None))

    loop = asyncio.get_event_loop()

    try:
        loop.run_until_complete(server.start())
    except KeyboardInterrupt:
        loop.run_until_complete(server.stop())
    finally:
        loop.close()
    print("done")
    exit(0)
