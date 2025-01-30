from abc import ABCMeta, abstractmethod

import click


class PasswordPrompt(metaclass=ABCMeta):
    @abstractmethod
    def get_password(self, key_id: str | None = None) -> bytes: ...

    @abstractmethod
    def create_password(self) -> bytes | None: ...


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
