from dataclasses import dataclass
from typing import BinaryIO

from dependency_injector.wiring import Provide, inject
from gnukek.constants import KeySize
from gnukek.keys import KeyPair

from gnukek_cli.constants import DEFAULT_KEY_SIZE
from gnukek_cli.container import Container
from gnukek_cli.keys.provider import KeyProvider
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
        key_provider: KeyProvider = Provide[Container.key_provider],
        password_prompt: PasswordPrompt = Provide[Container.password_prompt],
        output_buffer: BinaryIO = Provide[Container.output_buffer],
    ) -> None:
        self.context = context
        self._key_provider = key_provider
        self._password_prompt = password_prompt
        self._output_buffer = output_buffer

    def __call__(self) -> None:
        key_password = self._get_key_password()
        key_pair = KeyPair.generate(self.context.key_size)
        if self.context.save:
            self._key_provider.add_key_pair(key_pair, key_password)
        else:
            serialized_private_key = key_pair.serialize(password=key_password)
            self._output_buffer.write(serialized_private_key)

    def _get_key_password(self) -> bytes | None:
        if self.context.prompt_password:
            return self._password_prompt.create_password() or None
        return self.context.password
