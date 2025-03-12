import os
import sys
import threading
from collections.abc import Iterator
from io import BytesIO

from typing_extensions import Buffer

from gnukek_cli.extras.s3.constants import DOWNLOAD_BUFFER_TIMEOUT_SEC


class LazyEncryptionBuffer(BytesIO):
    """Buffer that encrypts data when reading."""

    def __init__(
        self,
        metadata: bytes,
        encryption_iterator: Iterator[bytes],
    ) -> None:
        super().__init__(metadata)
        self._metadata = metadata
        self._encryption_iterator = encryption_iterator

    def seekable(self) -> bool:
        return False

    def read(self, size: int | None = -1, /) -> bytes:
        previous_position = self.tell()
        bytes_to_read = size if size and size >= 0 else sys.maxsize

        self.seek(0, os.SEEK_END)

        bytes_processed = 0
        while (
            chunk := next(self._encryption_iterator, b"")
        ) and bytes_processed < bytes_to_read:
            self.write(chunk)

        self.seek(previous_position)
        return super().read(size)


class EncryptedDownloadBuffer(BytesIO):
    def __init__(self) -> None:
        super().__init__()
        self._condition = threading.Condition()

        self._read_position = 0
        self._write_position = 0
        self._download_finished = False

    def seekable(self) -> bool:
        return False

    def set_download_finished(self) -> None:
        self._download_finished = True

    def write(self, data: Buffer) -> int:
        with self._condition:
            self.seek(self._write_position)
            bytes_written = super().write(data)
            self._write_position = self.tell()
            self._condition.notify()
            return bytes_written

    def read(self, size: int | None = -1) -> bytes:
        if not size or size < 0:
            raise ValueError("Reading the whole buffer is not supported")

        with self._condition:
            self._condition.wait_for(
                lambda: self._download_finished
                or self._get_unprocessed_buffer_size() >= size,
                timeout=DOWNLOAD_BUFFER_TIMEOUT_SEC,
            )

            self.seek(self._read_position)
            read_data = super().read(size)
            self._read_position = self.tell()
            return read_data

    def _get_unprocessed_buffer_size(self) -> int:
        previous_position = self.tell()

        self.seek(0, os.SEEK_END)
        buffer_size = self.tell()
        self.seek(previous_position)

        return buffer_size - self._read_position
