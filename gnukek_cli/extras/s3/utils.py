import os
import sys
import threading
from collections import deque
from collections.abc import Iterator
from io import BytesIO
from types import TracebackType
from typing import BinaryIO

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


class StreamingDecryptionBuffer(BinaryIO):
    def __init__(self) -> None:
        self._condition = threading.Condition()

        self._chunks: deque[bytes] = deque()
        self._download_finished = False

    def set_download_finished(self) -> None:
        with self._condition:
            self._download_finished = True

    def write(self, chunk: bytes) -> int:  # type: ignore
        with self._condition:
            self._chunks.append(chunk)
            self._condition.notify()
            return len(chunk)

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            raise ValueError("Reading the whole buffer is not supported")

        with self._condition:
            read_bytes = b""

            while len(read_bytes) < size:
                self._condition.wait_for(
                    lambda: self._chunks or self._download_finished,
                    timeout=DOWNLOAD_BUFFER_TIMEOUT_SEC,
                )

                try:
                    chunk = self._chunks.popleft()
                except IndexError:
                    chunk = b""

                if not chunk and self._download_finished:
                    return read_bytes

                remaining_bytes = size - len(read_bytes)
                read_bytes += chunk[:remaining_bytes]

                if len(chunk) > remaining_bytes:
                    self._chunks.appendleft(chunk[remaining_bytes:])

            return read_bytes

    def __enter__(self) -> BinaryIO:
        return self

    def __exit__(
        self,
        type: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        pass

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def close(self) -> None:
        pass

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False

    def tell(self) -> int:
        raise OSError("tell() is not supported")

    def truncate(self, size: int | None = None) -> int:
        raise OSError("truncate() is not supported")

    def fileno(self) -> int:
        raise OSError("fileno() is not supported")

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        raise OSError("seek() is not supported")

    def readline(self, size: int = -1) -> bytes:
        raise OSError("readline() is not supported")

    def readlines(self, hint: int = -1) -> list[bytes]:
        raise OSError("readlines() is not supported")

    def writelines(self, lines: list[bytes]) -> None:  # type: ignore
        raise OSError("writelines() is not supported")

    def __iter__(self) -> Iterator[bytes]:
        raise OSError("__iter__() is not supported")

    def __next__(self) -> bytes:
        raise OSError("__next__() is not supported")
