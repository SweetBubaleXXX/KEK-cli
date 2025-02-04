from dataclasses import dataclass
from io import RawIOBase
from typing import BinaryIO

from dependency_injector.wiring import Provide, inject
from gnukek.constants import CHUNK_LENGTH
from gnukek.utils import extract_key_id, preprocess_encrypted_stream

from gnukek_cli.config import SettingsProvider
from gnukek_cli.container import Container
from gnukek_cli.exceptions import KeyNotFoundError
from gnukek_cli.keys import PrivateKeyStorage
from gnukek_cli.passwords import PasswordPrompt


@dataclass
class DecryptContext:
    input_file: RawIOBase
    output_file: BinaryIO
    chunk_length: int = CHUNK_LENGTH


class DecryptHandler:
    @inject
    def __init__(
        self,
        context: DecryptContext,
        *,
        private_key_storage: PrivateKeyStorage = Provide[Container.private_key_storage],
        settings_provider: SettingsProvider = Provide[Container.settings_provider],
        password_prompt: PasswordPrompt = Provide[Container.password_prompt],
    ) -> None:
        self.context = context
        self._private_key_storage = private_key_storage
        self._password_prompt = password_prompt
        self._settings_provider = settings_provider

    def __call__(self) -> None:
        self._settings = self._settings_provider.get_settings()

        if self.context.chunk_length:
            self._decrypt_chunked()
        else:
            self._decrypt_inplace()

    def _decrypt_chunked(self) -> None:
        preprocessed_stream = preprocess_encrypted_stream(self.context.input_file)

        key_id = preprocessed_stream.key_id.hex()

        if key_id not in self._settings.private:
            raise KeyNotFoundError(key_id)

        key_pair = self._private_key_storage.read_private_key(
            key_id, self._password_prompt.get_password_callback(key_id=key_id)
        )
        decryption_iterator = key_pair.decrypt_stream(
            preprocessed_stream, chunk_length=self.context.chunk_length
        )
        for chunk in decryption_iterator:
            self.context.output_file.write(chunk)

    def _decrypt_inplace(self) -> None:
        encrypted_content = self.context.input_file.read()
        key_id_bytes = extract_key_id(encrypted_content)
        key_id = key_id_bytes.hex()

        if key_id not in self._settings.private:
            raise KeyNotFoundError(key_id)

        key_pair = self._private_key_storage.read_private_key(
            key_id, self._password_prompt.get_password_callback(key_id=key_id)
        )
        decrypted_content = key_pair.decrypt(encrypted_content)
        self.context.output_file.write(decrypted_content)
