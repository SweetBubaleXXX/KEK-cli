import functools
from abc import ABCMeta, abstractmethod
from typing import Callable

import click

PromptPasswordCallback = Callable[[], bytes]


class PasswordPrompt(metaclass=ABCMeta):
    @abstractmethod
    def get_password(self, key_id: str | None = None) -> bytes: ...

    @abstractmethod
    def create_password(self) -> bytes | None: ...

    def get_password_callback(
        self, key_id: str | None = None
    ) -> PromptPasswordCallback:
        return functools.partial(self.get_password, key_id=key_id)


class ClickPasswordPrompt(PasswordPrompt):
    def get_password(self, key_id: str | None = None) -> bytes:
        prompt_text = f"Enter password for {key_id}" if key_id else "Enter password"
        return click.prompt(prompt_text, hide_input=True, err=True).encode()

    def create_password(self) -> bytes:
        return click.prompt(
            "Enter password",
            default="",
            show_default=False,
            hide_input=True,
            confirmation_prompt=True,
            err=True,
        ).encode()
