import asyncio
from datetime import datetime
from enum import Enum, auto

from clicker import SusClient
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from textual import on
from textual.app import App, ComposeResult
from textual.widgets import LoadingIndicator

from clique.msgs import LoginMsg, SendMsg
from clique.schema import LoginRequest, LookupRequest, LookupResponse
from clique.screens.inbox import InboxScreen
from clique.screens.login import LoginScreen
from clique.screens.settings import SettingsScreen

KEEP_ALIVE_INTERVAL = 3


class CliqState(Enum):
    """The state of the application."""
    CONNECTING = auto()
    LOOKUP = auto()
    LOGGING_IN = auto()
    CONNECTED = auto()


class Cliq(App):
    BINDINGS = [("ctrl+q", "quit", "Quit"), ("ctrl+s", "settings", "Settings")]
    CSS_PATH = "style/cliq.tcss"

    SCREENS = {"inbox": InboxScreen(), "settings": SettingsScreen(),
               "login": LoginScreen()}

    client: SusClient
    last_send: datetime
    last_recv: datetime

    state: CliqState

    username: str
    password: str

    def compose(self) -> ComposeResult:
        """Compose the widget."""
        yield LoadingIndicator()

    async def on_mount(self) -> None:
        with open("server.pub") as f:
            key = f.read()
        asyncio.create_task(self.connect(("localhost", 42069), key))

    def action_settings(self) -> None:
        """An action to go to the settings screen."""
        self.push_screen("settings")

    def action_quit(self) -> None:
        """An action to quit the application."""
        self.exit()

    def on_send_msg(self, msg: SendMsg) -> None:
        """Handle a new message."""
        asyncio.create_task(self.send(
            f"{msg.channel}\n{msg.user}\n"
            f"{msg.stamp.isoformat()}\n{msg.message}".encode()
        ))
        msg.stop()

    async def recv_handler(self, _addr: tuple[str, int], _id: int,
                           data: bytes) -> None:
        """Handle a message from the server."""
        self.last_recv = datetime.now()
        if data == b"keep alive":
            return

        match self.state:
            case CliqState.LOOKUP:
                lookup: LookupResponse = LookupResponse.unpack(data)
                uid: int = lookup.id
                salt: bytes = lookup.salt
                kdf = PBKDF2HMAC(
                    length=32,
                    salt=salt,
                    algorithm="blake2s",

                )
                key: bytes = kdf.derive(self.password.encode())
                del self.password, kdf

                request = LoginRequest(uid, 0, key)
                self.state = CliqState.LOGGING_IN
                asyncio.create_task(self.send(request.pack()))
                return
            case CliqState.LOGGING_IN:
                if data != b"ok":
                    self.exit(message="Failed to login")
                    return
                self.state = CliqState.CONNECTED
                await self.push_screen("inbox")
                return

    async def connect(self, addr: tuple[str, int], key: str) -> None:
        """Connect to the server."""
        self.state = CliqState.CONNECTING
        self.client = SusClient(addr, key, b"cliq")
        try:
            await self.client.start([self.recv_handler])
        except (TimeoutError, ConnectionError):
            self.exit(message="Failed to connect to server")
        self.last_send = self.last_recv = datetime.now()
        asyncio.create_task(self.keep_alive())
        await self.push_screen("login")

    async def keep_alive(self) -> None:
        """Keep the connection alive."""
        await self.send(b"keep alive")
        while True:
            await asyncio.sleep(KEEP_ALIVE_INTERVAL)
            now = datetime.now()
            if (now - self.last_send).total_seconds() > KEEP_ALIVE_INTERVAL:
                await self.send(b"keep alive")
            # if (
            #     self.last_recv < now and
            #     (now - self.last_recv).total_seconds() > KEEP_ALIVE_INTERVAL * 2
            # ):
            #     self.exit(message="Connection timed out")
            #     return  # unreachable

    async def send(self, data: bytes) -> None:
        """Send data to the server."""

        async def _task():
            print(f">>> {data.decode()}")
            self.client.send(data)
            self.last_send = datetime.now()

        asyncio.create_task(_task())

    @on(LoginMsg)
    def login(self, msg: LoginMsg) -> None:
        """Handle a login message."""
        self.username = msg.username
        self.password = msg.password
        request = LookupRequest(msg.username)
        self.state = CliqState.LOOKUP
        asyncio.create_task(self.send(request.pack()))
        msg.stop()


if __name__ == "__main__":
    app = Cliq()
    app.run()
