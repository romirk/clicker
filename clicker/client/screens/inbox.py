from textual import on
from textual.app import ComposeResult
from textual.containers import Center, Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, Label, OptionList, Static

from clique.screens.chat import ChatScreen


class Inbox(Static):
    @on(OptionList.OptionSelected)
    def _on_option_selected(self, event: OptionList.OptionSelected) -> None:
        option = event.option.prompt
        self.app.push_screen(ChatScreen(option))

    def compose(self) -> ComposeResult:
        with Center():
            yield Label("Inbox", id="inbox-title")
        with Center():
            yield OptionList(
                "Server",
                name="inbox",
            )
        

class InboxScreen(Screen):
    SUB_TITLE = "Inbox"

    def compose(self) -> ComposeResult:
        yield Header()
        yield Inbox()
        yield Footer()
