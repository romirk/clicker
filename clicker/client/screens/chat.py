from datetime import datetime

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, \
    VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, ListItem, \
    ListView, \
    Static

from clique.msgs import NewMsg, SendMsg


class ChatMessage(Static):
    """A chat message."""

    def __init__(self, channel: str, user: str, stamp: datetime,
                 message: str) -> None:
        """Initialize."""
        super().__init__()
        self.channel = channel
        self.user = user
        self.stamp = stamp
        self.text = message
        if user == "me":
            self.add_class("me")

    def compose(self) -> ComposeResult:
        """Compose the widget."""
        yield Vertical(
            Label(self.user, classes="sender"),
            Static(self.text, classes="text"),
            Label(datetime.now().strftime("%H:%M:%S"), classes="stamp"),
            classes="message-container",
        )


class ChatWindow(VerticalScroll):

    def __init__(self) -> None:
        """Initialize."""
        super().__init__()

    def compose(self) -> ComposeResult:
        """Compose the widget."""
        yield ListView(id="chat-window", name="messages")


class ChatTextBox(Static):
    def __init__(self, channel: str, user: str) -> None:
        """Initialize."""
        self.channel = channel
        self.user = user
        super().__init__()
        self.add_class("chat-text-box")

    def on_mount(self) -> None:
        """Mount."""
        self.query_one("#chat-text-box").focus()

    def compose(self) -> ComposeResult:
        """Compose the widget."""
        yield Horizontal(
            Input(name="message", placeholder="Type a message...",
                  id="chat-text-box"),
            Button("Send", name="send")
        )

    @on(Input.Submitted, "#chat-text-box")
    def _on_submit(self, event: Input.Submitted) -> None:
        """Send a message."""
        message = event.value
        event.input.value = ""
        self.post_message(SendMsg(self.channel, self.user, message))
        self.post_message(NewMsg(self.channel, self.user, message))
        event.stop()


class ChatScreen(Screen):
    BINDINGS = [("ctrl+b", "back", "Back")]

    def __init__(self, chatter: str) -> None:
        """Initialize."""
        super().__init__()
        self.chatter = chatter
        self.user = "me"
        # noinspection PyTypeChecker
        self.sub_title = chatter

    def compose(self) -> ComposeResult:
        yield Header()
        yield Vertical(
            ChatWindow(),
            ChatTextBox(self.chatter, self.user),
            classes="main",
        )
        yield Footer()

    def action_back(self) -> None:
        """An action to go back to the inbox."""
        self.app.pop_screen()

    @on(NewMsg)
    def msg(self, msg: NewMsg) -> None:
        """Handle a new message."""
        print("refreshing")
        self.query_one(ListView).append(
            ListItem(ChatMessage(msg.channel, msg.user, msg.stamp,
                                 msg.message)))
        msg.stop()
        # self.refresh()
