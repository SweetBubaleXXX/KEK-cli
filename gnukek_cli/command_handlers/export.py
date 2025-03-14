import logging
from dataclasses import dataclass
from typing import BinaryIO

from dependency_injector.wiring import Provide, inject

from gnukek_cli.config import SettingsProvider
from gnukek_cli.container import Container
from gnukek_cli.keys.storages import PrivateKeyStorage, PublicKeyStorage
from gnukek_cli.utils.exceptions import KeyNotFoundError
from gnukek_cli.utils.passwords import PasswordPrompt

logger = logging.getLogger(__name__)


@dataclass
class ExportContext:
    key_id: str
    file: BinaryIO
    public: bool = False
    prompt_password: bool = True


class ExportHandler:
    @inject
    def __init__(
        self,
        context: ExportContext,
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
        if self.context.public:
            logger.debug(f"Exporting public key: {self.context.key_id}")
            self._export_public_key()
        else:
            logger.debug(f"Exporting private key: {self.context.key_id}")
            self._export_private_key()

    def _export_private_key(self) -> None:
        settings = self._settings_provider.get_settings()
        if self.context.key_id not in settings.private:
            raise KeyNotFoundError(self.context.key_id)

        if not self.context.prompt_password:
            logger.debug("Returning raw private key")
            self._serialize_raw_private_key()
        else:
            self._serialize_private_key()

    def _serialize_private_key(self):
        key_pair = self._private_key_storage.read_private_key(
            self.context.key_id, self._password_prompt.get_password
        )
        password = self._password_prompt.create_password() or None
        serialized_key = key_pair.serialize(password=password)
        self.context.file.write(serialized_key)

    def _serialize_raw_private_key(self):
        serialized_key = self._private_key_storage.read_private_key_raw(
            self.context.key_id
        )
        self.context.file.write(serialized_key)

    def _export_public_key(self) -> None:
        settings = self._settings_provider.get_settings()

        if self.context.key_id in settings.public:
            logger.debug("Returning public key directly")
            self._serialize_public_key()
        elif self.context.key_id in settings.private:
            logger.debug("Exporting public key from private key")
            self._serialize_public_key_from_private()
        else:
            raise KeyNotFoundError(self.context.key_id)

    def _serialize_public_key_from_private(self):
        key_pair = self._private_key_storage.read_private_key(
            self.context.key_id,
            self._password_prompt.get_password_callback(key_id=self.context.key_id),
        )
        serialized_key = key_pair.public_key.serialize()
        self.context.file.write(serialized_key)

    def _serialize_public_key(self):
        public_key = self._public_key_storage.read_public_key(self.context.key_id)
        serialized_key = public_key.serialize()
        self.context.file.write(serialized_key)
