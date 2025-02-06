from dataclasses import dataclass
from typing import BinaryIO

from dependency_injector.wiring import Provide, inject
from gnukek.constants import CHUNK_LENGTH
from gnukek.exceptions import VerificationError

from gnukek_cli.container import Container
from gnukek_cli.keys.provider import KeyProvider


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
        key_provider: KeyProvider = Provide[Container.key_provider],
    ) -> None:
        self.context = context
        self._key_provider = key_provider

    def __call__(self) -> None:
        public_key = self._key_provider.get_public_key(self.context.key_id)

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
