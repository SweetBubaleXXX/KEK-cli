import logging
from dataclasses import dataclass
from typing import BinaryIO

from dependency_injector.wiring import Provide, inject
from gnukek.constants import CHUNK_LENGTH, LATEST_KEK_VERSION

from gnukek_cli.container import Container
from gnukek_cli.keys.provider import KeyProvider

logger = logging.getLogger(__name__)


@dataclass
class EncryptContext:
    input_file: BinaryIO
    output_file: BinaryIO
    key_id: str | None = None
    chunk_length: int = CHUNK_LENGTH
    version: int = LATEST_KEK_VERSION


class EncryptHandler:
    @inject
    def __init__(
        self,
        context: EncryptContext,
        *,
        key_provider: KeyProvider = Provide[Container.key_provider],
    ) -> None:
        self.context = context
        self._key_provider = key_provider

    def __call__(self) -> None:
        public_key = self._key_provider.get_public_key(self.context.key_id)

        logger.info(f"Using key: {public_key.key_id.hex()}")
        logger.debug(f"Using v{self.context.version} encryption")

        encryptor = public_key.get_encryptor(version=self.context.version)
        metadata = encryptor.get_metadata()

        if self.context.chunk_length:
            logger.debug("Using chunk encryption")
            logger.debug(f"Chunk size: {self.context.chunk_length}")
            self.context.output_file.write(metadata)
            for chunk in encryptor.encrypt_stream(
                self.context.input_file,
                chunk_length=self.context.chunk_length,
            ):
                self.context.output_file.write(chunk)
        else:
            logger.debug("Using inplace encryption")
            original_content = self.context.input_file.read()
            encrypted_content = encryptor.encrypt(original_content)
            self.context.output_file.write(metadata)
            self.context.output_file.write(encrypted_content)

        logger.debug("Encryption finished")
