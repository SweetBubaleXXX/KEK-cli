from dataclasses import dataclass
from typing import BinaryIO

from dependency_injector.wiring import Provide, inject
from gnukek.constants import CHUNK_LENGTH

from gnukek_cli.container import Container
from gnukek_cli.keys.provider import KeyProvider


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
        key_provider: KeyProvider = Provide[Container.key_provider],
    ) -> None:
        self.context = context
        self._key_provider = key_provider

    def __call__(self) -> None:
        key_pair = self._key_provider.get_key_pair(self.context.key_id)

        if self.context.chunk_length:
            signature = key_pair.sign_stream(
                self.context.input_file, chunk_size=self.context.chunk_length
            )
        else:
            content = self.context.input_file.read()
            signature = key_pair.sign(content)

        self.context.output_file.write(signature)
