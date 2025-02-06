from dataclasses import dataclass
from typing import BinaryIO

from dependency_injector.wiring import Provide, inject
from gnukek.constants import CHUNK_LENGTH
from gnukek.exceptions import VerificationError
from gnukek.keys import PublicKey

from gnukek_cli.config import SettingsProvider
from gnukek_cli.container import Container
from gnukek_cli.exceptions import KeyNotFoundError
from gnukek_cli.keys import PrivateKeyStorage, PublicKeyStorage
from gnukek_cli.passwords import PasswordPrompt


@dataclass
class VerifyContext:
    signature_file: BinaryIO
    original_file: BinaryIO
    key_id: str | None = None
    chunk_length: int = CHUNK_LENGTH


class VerifyHandler:
    @inject
    def __init__(
        self,
        context: VerifyContext,
        *,
        public_key_storage: PublicKeyStorage = Provide[Container.public_key_storage],
        private_key_storage: PrivateKeyStorage = Provide[Container.private_key_storage],
        settings_provider: SettingsProvider = Provide[Container.settings_provider],
        password_prompt: PasswordPrompt = Provide[Container.password_prompt],
    ) -> None:
        self.context = context
        self._public_key_storage = public_key_storage
        self._private_key_storage = private_key_storage
        self._settings_provider = settings_provider
        self._password_prompt = password_prompt

    def __call__(self) -> None:
        public_key = self._get_public_key()

        signature = self.context.signature_file.read()

        if self.context.chunk_length:
            is_valid = public_key.verify_stream(
                signature,
                buffer=self.context.original_file,
                chunk_length=self.context.chunk_length,
            )
        else:
            is_valid = public_key.verify(
                signature,
                message=self.context.original_file.read(),
            )

        if not is_valid:
            raise VerificationError("Signature is not valid")

    def _get_public_key(self) -> PublicKey:
        settings = self._settings_provider.get_settings()

        key_id = self.context.key_id or settings.default
        if not key_id:
            raise KeyNotFoundError("default")

        if key_id in settings.public:
            return self._public_key_storage.read_public_key(key_id)
        elif key_id in settings.private:
            key_pair = self._private_key_storage.read_private_key(
                key_id,
                self._password_prompt.get_password_callback(key_id=key_id),
            )
            return key_pair.public_key
        else:
            raise KeyNotFoundError(key_id)
