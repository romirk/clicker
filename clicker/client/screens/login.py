from textual import on
from textual.app import ComposeResult
from textual.containers import Center, Horizontal, Middle, Vertical
from textual.screen import Screen
from textual.widgets import Input, Label, LoadingIndicator

from clique.msgs import LoginMsg


class LoginWindow(Vertical):
    username: str
    password: str

    def compose(self) -> ComposeResult:
        yield Label("Login", classes="login-title")
        with Horizontal():
            yield Label("Username", classes="login-label")
            yield Input(name="username", classes="login-input", id="username")
        with Horizontal():
            yield Label("Password", classes="login-label")
            yield Input(name="password", classes="login-input", password=True,
                        id="password")

    @on(Input.Submitted, "#username")
    def _on_username_submitted(self, _) -> None:
        """Handle the username being submitted."""
        self.query_one("#password").focus()

    @on(Input.Submitted, "#password")
    def _on_password_submitted(self, _) -> None:
        """Handle the password being submitted."""
        self.post_message(LoginMsg(self.query_one("#username", Input).value,
                                   self.query_one("#password", Input).value))
        LoadingIndicator().apply(self)


class LoginScreen(Screen):
    SUB_TITLE = "Login"
    BINDINGS = [("ctrl+s", "settings")]

    def compose(self) -> ComposeResult:
        with Middle():
            with Center():
                yield LoginWindow(id="login-window")

    def action_settings(self) -> None:
        """Catches the settings action."""
        pass
