from collections.abc import Iterable
from dataclasses import dataclass
from typing import BinaryIO

from dependency_injector.wiring import Provide, inject
from gnukek.constants import SerializedKeyType
from gnukek.keys import KeyPair, PublicKey
from gnukek.utils import get_key_type

from gnukek_cli.config import SettingsProvider
from gnukek_cli.container import Container
from gnukek_cli.keys import PrivateKeyStorage, PublicKeyStorage
from gnukek_cli.passwords import PasswordPrompt


@dataclass
class ImportKeysContext:
    key_files: Iterable[BinaryIO]
    password: bytes | None = None
    prompt_password: bool = True


class ImportKeysHandler:
    @inject
    def __init__(
        self,
        context: ImportKeysContext,
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
        self._settings = self._settings_provider.get_settings()

        for file in self.context.key_files:
            self._import_key(file)

        self._settings_provider.save_settings(self._settings)

    def _import_key(self, file: BinaryIO) -> None:
        serialized_key = file.read()
        key_type = get_key_type(serialized_key)

        if key_type == SerializedKeyType.PUBLIC_KEY:
            public_key = PublicKey.load(serialized_key)
            self._import_public_key(public_key)
        else:
            key_password: bytes | None = None
            if key_type == SerializedKeyType.ENCRYPTED_PRIVATE_KEY:
                key_password = self._prompt_password()

            key_pair = KeyPair.load(serialized_key, password=key_password)
            key_id_hex = key_pair.key_id.hex()
            self._private_key_storage.save_private_key(key_pair, key_password)
            if key_id_hex not in self._settings.private:
                self._settings.private.append(key_id_hex)
            self._import_public_key(key_pair.public_key)
            if not self._settings.default:
                self._settings.default = key_id_hex

    def _import_public_key(self, public_key: PublicKey) -> None:
        self._public_key_storage.save_public_key(public_key)
        if public_key.key_id.hex() not in self._settings.public:
            self._settings.public.append(public_key.key_id.hex())

    def _prompt_password(self) -> bytes | None:
        if self.context.prompt_password:
            return self._password_prompt.get_password() or None
        return self.context.password
