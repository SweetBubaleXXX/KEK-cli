from abc import ABCMeta, abstractmethod

import click


class PasswordPrompt(metaclass=ABCMeta):
    @abstractmethod
    def get_password(self, key_id: str) -> bytes: ...

    @abstractmethod
    def create_password(self) -> bytes: ...


class ClickPasswordPrompt(PasswordPrompt):
    def get_password(self, key_id: str) -> bytes:
        return click.prompt(f"Enter password for {key_id}", hide_input=True)

    def create_password(self) -> bytes:
        return click.prompt("Enter password", hide_input=True, confirmation_prompt=True)
