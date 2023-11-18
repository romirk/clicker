from datetime import datetime

from textual.message import Message


class _Msg(Message):
    """Send a message."""

    def __init__(self, channel: str, user: str, message: str,
                 stamp: datetime = None) -> None:
        """Initialize."""
        print(f"#{channel} {user}: {message}")
        self.message = message
        self.user = user
        self.channel = channel
        self.stamp = stamp or datetime.now()
        super().__init__()


class SendMsg(_Msg):
    pass


class NewMsg(_Msg):
    pass


class LoginMsg(Message):
    """Login message."""

    def __init__(self, username: str, password: str) -> None:
        """Initialize."""
        self.username = username
        self.password = password
        super().__init__()
