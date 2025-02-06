from collections.abc import Iterable
from dataclasses import dataclass
from typing import BinaryIO

from dependency_injector.wiring import Provide, inject
from gnukek.constants import SerializedKeyType
from gnukek.keys import KeyPair, PublicKey
from gnukek.utils import get_key_type

from gnukek_cli.container import Container
from gnukek_cli.keys.provider import KeyProvider
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
        key_provider: KeyProvider = Provide[Container.key_provider],
        password_prompt: PasswordPrompt = Provide[Container.password_prompt],
    ) -> None:
        self.context = context
        self._key_provider = key_provider
        self._password_prompt = password_prompt

    def __call__(self) -> None:
        for file in self.context.key_files:
            self._import_key(file)

    def _import_key(self, file: BinaryIO) -> None:
        serialized_key = file.read()
        key_type = get_key_type(serialized_key)

        if key_type == SerializedKeyType.PUBLIC_KEY:
            public_key = PublicKey.load(serialized_key)
            self._key_provider.add_public_key(public_key)
        else:
            key_password: bytes | None = None
            if key_type == SerializedKeyType.ENCRYPTED_PRIVATE_KEY:
                key_password = self._prompt_password()

            key_pair = KeyPair.load(serialized_key, password=key_password)
            self._key_provider.add_key_pair(key_pair, key_password)

    def _prompt_password(self) -> bytes | None:
        if self.context.prompt_password:
            return self._password_prompt.get_password() or None
        return self.context.password
