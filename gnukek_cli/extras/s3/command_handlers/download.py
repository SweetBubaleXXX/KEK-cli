import logging
import threading
from dataclasses import dataclass
from typing import BinaryIO

import boto3
from dependency_injector.wiring import Provide, inject
from gnukek.utils import preprocess_encrypted_stream

from gnukek_cli.container import Container
from gnukek_cli.extras.s3.buffers import StreamingDecryptionBuffer
from gnukek_cli.keys.provider import KeyProvider

logger = logging.getLogger(__name__)


@dataclass
class DownloadContext:
    bucket_name: str
    object_name: str
    output_file: BinaryIO


class DownloadHandler:
    @inject
    def __init__(
        self,
        context: DownloadContext,
        *,
        key_provider: KeyProvider = Provide[Container.key_provider],
    ) -> None:
        self.context = context
        self._key_provider = key_provider

    def __call__(self) -> None:
        s3_client = boto3.client("s3")

        download_buffer = StreamingDecryptionBuffer()

        def fetch_file():
            logger.debug("Downloading file")
            s3_client.download_fileobj(
                self.context.bucket_name, self.context.object_name, download_buffer
            )
            download_buffer.set_download_finished()
            logger.debug("Download finished")

        download_thread = threading.Thread(target=fetch_file)
        logger.debug("Starting download thread")
        download_thread.start()

        preprocessed_stream = preprocess_encrypted_stream(download_buffer)
        key_id = preprocessed_stream.key_id.hex()

        logger.info(f"Data is encrypted with key: {key_id}")
        key_pair = self._key_provider.get_key_pair(key_id)

        decryption_iterator = key_pair.decrypt_stream(preprocessed_stream)
        for chunk in decryption_iterator:
            self.context.output_file.write(chunk)

        logger.debug("Decryption finished")

        download_thread.join()
        logger.debug("Download thread finished")
