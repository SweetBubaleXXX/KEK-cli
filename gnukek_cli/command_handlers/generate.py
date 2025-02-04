from dataclasses import dataclass
from typing import BinaryIO

from dependency_injector.wiring import Provide, inject
from gnukek import KeyPair
from gnukek.constants import KeySize

from gnukek_cli.config import SettingsProvider
from gnukek_cli.constants import DEFAULT_KEY_SIZE
from gnukek_cli.container import Container
from gnukek_cli.keys import PrivateKeyStorage, PublicKeyStorage
from gnukek_cli.passwords import PasswordPrompt


@dataclass
class GenerateKeyContext:
    key_size: KeySize = DEFAULT_KEY_SIZE  # type: ignore
    password: bytes | None = None
    prompt_password: bool = True
    save: bool = True


class GenerateKeyHandler:
    @inject
    def __init__(
        self,
        context: GenerateKeyContext,
        *,
        public_key_storage: PublicKeyStorage = Provide[Container.public_key_storage],
        private_key_storage: PrivateKeyStorage = Provide[Container.private_key_storage],
        settings_provider: SettingsProvider = Provide[Container.settings_provider],
        password_prompt: PasswordPrompt = Provide[Container.password_prompt],
        output_buffer: BinaryIO = Provide[Container.output_buffer],
    ) -> None:
        self.context = context
        self._public_key_storage = public_key_storage
        self._private_key_storage = private_key_storage
        self._settings_provider = settings_provider
        self._password_prompt = password_prompt
        self._output_buffer = output_buffer

    def __call__(self) -> None:
        key_password = self._get_key_password()
        key_pair = KeyPair.generate(self.context.key_size)
        if self.context.save:
            self._save_key_pair(key_pair, key_password)
        else:
            serialized_private_key = key_pair.serialize(password=key_password)
            self._output_buffer.write(serialized_private_key)

    def _get_key_password(self) -> bytes | None:
        if self.context.prompt_password:
            return self._password_prompt.create_password() or None
        return self.context.password

    def _save_key_pair(self, key_pair: KeyPair, key_password: bytes | None) -> None:
        self._private_key_storage.save_private_key(key_pair, key_password)
        self._public_key_storage.save_public_key(key_pair.public_key)
        self._update_settings(key_pair)

    def _update_settings(self, key_pair: KeyPair) -> None:
        settings = self._settings_provider.get_settings()
        key_id_hex = key_pair.key_id.hex()
        settings.private.append(key_id_hex)
        settings.public.append(key_id_hex)
        if not settings.default:
            settings.default = key_id_hex
        self._settings_provider.save_settings(settings)
