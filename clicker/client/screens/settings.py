from textual import on
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import ContentSwitcher, Footer, Header, Label, ListItem, \
    ListView, \
    Static, Switch

import clique


class General(Static):
    def compose(self) -> ComposeResult:
        """Compose the widget."""
        yield Label("General", classes="settings-content-title")


class Appearance(Static):
    def compose(self) -> ComposeResult:
        """Compose the widget."""
        yield Label("Appearance", classes="settings-content-title")

        with Horizontal(classes="settings-setting"):
            yield Label("Dark mode", classes="settings-setting-title")
            yield Container(Switch(name="dark-mode", id="dark-mode-switch"),
                            classes="settings-setting-value")

    def on_mount(self) -> None:
        """Mount."""
        self.query_one("#dark-mode-switch").value = self.app.dark

    @on(Switch.Changed, "#dark-mode-switch")
    def _on_dark_mode_changed(self, event: Switch.Changed) -> None:
        """Change the dark mode."""
        self.app.dark = event.value


class Accounts(Static):
    def compose(self) -> ComposeResult:
        """Compose the widget."""
        yield Label("Accounts", classes="settings-content-title")


class About(Static):
    def compose(self) -> ComposeResult:
        """Compose the widget."""
        yield Label("About", classes="settings-content-title")
        with Vertical():
            yield Label("Clique", classes="settings-content-subtitle")
            yield Label(f"Version {clique.__version__}",
                        classes="settings-content-subtitle")


class Settings(Static):
    """Settings."""

    def compose(self) -> ComposeResult:
        """Compose the widget."""
        with Horizontal():
            with Vertical(id="settings-list-container"):
                yield Label("Settings", id="settings-title")
                yield ListView(
                    ListItem(Label("General"), name="general",
                             classes="settings-item"),
                    ListItem(Label("Appearance"), name="appearance",
                             classes="settings-item"),
                    ListItem(Label("Accounts"), name="accounts",
                             classes="settings-item"),
                    ListItem(Label("About"), name="about",
                             classes="settings-item"),
                    id="settings-list",
                )
            with ContentSwitcher(name="content", id="settings-content"):
                yield General(id="settings-general", classes="settings-content")
                yield Appearance(id="settings-appearance",
                                 classes="settings-content")
                yield Accounts(id="settings-accounts",
                               classes="settings-content")
                yield About(id="settings-about", classes="settings-content")

    def on_mount(self) -> None:
        """Mount."""
        self.query_one(
            "#settings-content").current = "settings-general"

    @on(ListView.Selected)
    def _on_selected(self, event: ListView.Selected) -> None:
        name = "settings-" + event.item.name
        self.query_one("#settings-content").current = name
        self.query_one("#" + name).focus()


class SettingsScreen(Screen):
    BINDINGS = [("ctrl+s,ctrl+b", "back", "Back")]

    def action_back(self) -> None:
        """An action to go back to the inbox."""
        self.app.pop_screen()

    def compose(self) -> ComposeResult:
        yield Header()
        yield Settings()
        yield Footer()
