import logging
from dataclasses import dataclass
from io import BytesIO
from typing import BinaryIO

import boto3
from dependency_injector.wiring import Provide, inject
from gnukek.constants import LATEST_KEK_VERSION

from gnukek_cli.container import Container
from gnukek_cli.extras.s3.buffers import LazyEncryptionBuffer
from gnukek_cli.extras.s3.constants import ENCRYPTION_CHUNK_LENGTH
from gnukek_cli.keys.provider import KeyProvider

logger = logging.getLogger(__name__)


@dataclass
class UploadContext:
    input_file: BinaryIO
    bucket_name: str
    object_name: str
    key_id: str | None = None
    no_chunk: bool = False
    version: int = LATEST_KEK_VERSION


class UploadHandler:
    @inject
    def __init__(
        self,
        context: UploadContext,
        *,
        key_provider: KeyProvider = Provide[Container.key_provider],
    ) -> None:
        self.context = context
        self._key_provider = key_provider

    def __call__(self) -> None:
        s3_client = boto3.client("s3")

        public_key = self._key_provider.get_public_key(self.context.key_id)

        logger.info(f"Using key: {public_key.key_id.hex()}")
        logger.debug(f"Using v{self.context.version} encryption")

        encryptor = public_key.get_encryptor(version=self.context.version)
        metadata = encryptor.get_metadata()

        if self.context.no_chunk:
            logger.debug("Using inplace encryption")

            original_content = self.context.input_file.read()

            encrypted_buffer = BytesIO()
            encrypted_buffer.write(metadata)
            encrypted_buffer.write(encryptor.encrypt(original_content))
            encrypted_buffer.seek(0)

            s3_client.upload_fileobj(
                encrypted_buffer, self.context.bucket_name, self.context.object_name
            )
        else:
            logger.debug("Using chunk encryption")

            encryption_iterator = encryptor.encrypt_stream(
                self.context.input_file,
                chunk_length=ENCRYPTION_CHUNK_LENGTH,
            )
            upload_buffer = LazyEncryptionBuffer(metadata, encryption_iterator)

            s3_client.upload_fileobj(
                upload_buffer, self.context.bucket_name, self.context.object_name
            )

        logger.debug("Encryption finished")
