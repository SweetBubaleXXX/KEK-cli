import logging
from dataclasses import dataclass
from typing import BinaryIO

from dependency_injector.wiring import Provide, inject
from gnukek.constants import CHUNK_LENGTH
from gnukek.utils import extract_key_id, preprocess_encrypted_stream

from gnukek_cli.container import Container
from gnukek_cli.keys.provider import KeyProvider

logger = logging.getLogger(__name__)


@dataclass
class DecryptContext:
    input_file: BinaryIO
    output_file: BinaryIO
    chunk_length: int = CHUNK_LENGTH


class DecryptHandler:
    @inject
    def __init__(
        self,
        context: DecryptContext,
        *,
        key_provider: KeyProvider = Provide[Container.key_provider],
    ) -> None:
        self.context = context
        self._key_provider = key_provider

    def __call__(self) -> None:
        if self.context.chunk_length:
            logger.debug("Using chunk decryption")
            logger.debug(f"Chunk size: {self.context.chunk_length}")
            self._decrypt_chunked()
        else:
            logger.debug("Using inplace decryption")
            self._decrypt_inplace()

    def _decrypt_chunked(self) -> None:
        preprocessed_stream = preprocess_encrypted_stream(self.context.input_file)

        key_id = preprocessed_stream.key_id.hex()
        logger.info(f"Data is encrypted with key: {key_id}")
        key_pair = self._key_provider.get_key_pair(key_id)

        decryption_iterator = key_pair.decrypt_stream(
            preprocessed_stream, chunk_length=self.context.chunk_length
        )
        for chunk in decryption_iterator:
            self.context.output_file.write(chunk)

        logger.debug("Decryption finished")

    def _decrypt_inplace(self) -> None:
        encrypted_content = self.context.input_file.read()

        key_id_bytes = extract_key_id(encrypted_content)
        key_id = key_id_bytes.hex()
        logger.info(f"Data is encrypted with key: {key_id}")
        key_pair = self._key_provider.get_key_pair(key_id)

        decrypted_content = key_pair.decrypt(encrypted_content)
        self.context.output_file.write(decrypted_content)

        logger.debug("Decryption finished")
