import sys
from collections.abc import Iterator
from io import BytesIO


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

        self.seek(0, 2)

        bytes_processed = 0
        while (
            chunk := next(self._encryption_iterator, b"")
        ) and bytes_processed < bytes_to_read:
            self.write(chunk)

        self.seek(previous_position)
        return super().read(size)
