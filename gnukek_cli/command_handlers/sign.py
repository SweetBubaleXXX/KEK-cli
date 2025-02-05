from dataclasses import dataclass
from typing import BinaryIO

from dependency_injector.wiring import Provide, inject
from gnukek.constants import CHUNK_LENGTH

from gnukek_cli.config import SettingsProvider
from gnukek_cli.container import Container
from gnukek_cli.exceptions import KeyNotFoundError
from gnukek_cli.keys import PrivateKeyStorage
from gnukek_cli.passwords import PasswordPrompt


@dataclass
class SignContext:
    input_file: BinaryIO
    output_file: BinaryIO
    key_id: str | None = None
    chunk_length: int = CHUNK_LENGTH


class SignHandler:
    @inject
    def __init__(
        self,
        context: SignContext,
        *,
        private_key_storage: PrivateKeyStorage = Provide[Container.private_key_storage],
        settings_provider: SettingsProvider = Provide[Container.settings_provider],
        password_prompt: PasswordPrompt = Provide[Container.password_prompt],
    ) -> None:
        self.context = context
        self._private_key_storage = private_key_storage
        self._settings_provider = settings_provider
        self._password_prompt = password_prompt

    def __call__(self) -> None:
        settings = self._settings_provider.get_settings()

        key_id = self.context.key_id or settings.default
        if not key_id:
            raise KeyNotFoundError("default")
        if key_id not in settings.private:
            raise KeyNotFoundError(key_id)

        key_pair = self._private_key_storage.read_private_key(
            key_id, self._password_prompt.get_password_callback(key_id)
        )

        if self.context.chunk_length:
            signature = key_pair.sign_stream(
                self.context.input_file, chunk_size=self.context.chunk_length
            )
        else:
            content = self.context.input_file.read()
            signature = key_pair.sign(content)

        self.context.output_file.write(signature)
