import os
import sys
import threading
from collections import deque
from collections.abc import Iterator
from functools import reduce
from types import TracebackType
from typing import BinaryIO

from gnukek_cli.extras.s3.constants import (
    DOWNLOAD_BUFFER_TIMEOUT_SEC,
    DOWNLOAD_MEMORY_LIMIT_BYTES,
)


class CustomBuffer(BinaryIO):
    """Base class for custom encryption/decryption buffers."""

    def __enter__(self) -> BinaryIO:
        return self

    def read(self, size: int = -1) -> bytes:
        raise NotImplementedError("read() is not supported")

    def write(self, chunk: bytes) -> int:  # type: ignore
        raise NotImplementedError("write() is not supported")

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
        raise NotImplementedError("tell() is not supported")

    def truncate(self, size: int | None = None) -> int:
        raise NotImplementedError("truncate() is not supported")

    def fileno(self) -> int:
        raise NotImplementedError("fileno() is not supported")

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        raise NotImplementedError("seek() is not supported")

    def readline(self, size: int = -1) -> bytes:
        raise NotImplementedError("readline() is not supported")

    def readlines(self, hint: int = -1) -> list[bytes]:
        raise NotImplementedError("readlines() is not supported")

    def writelines(self, lines: list[bytes]) -> None:  # type: ignore
        raise NotImplementedError("writelines() is not supported")

    def __iter__(self) -> Iterator[bytes]:
        raise NotImplementedError("__iter__() is not supported")

    def __next__(self) -> bytes:
        raise NotImplementedError("__next__() is not supported")


class LazyEncryptionBuffer(CustomBuffer):
    """Buffer that encrypts data when reading."""

    def __init__(
        self,
        metadata: bytes,
        encryption_iterator: Iterator[bytes],
    ) -> None:
        self._cached_chunk = metadata
        self._encryption_iterator = encryption_iterator

    def read(self, size: int = -1) -> bytes:
        requested_size = size if size >= 0 else sys.maxsize

        result_bytes = bytearray()

        while len(result_bytes) < requested_size:
            remaining_size = requested_size - len(result_bytes)

            if self._cached_chunk:
                chunk = self._cached_chunk
            else:
                chunk = next(self._encryption_iterator, b"")

            if not chunk:
                break

            result_bytes.extend(chunk[:remaining_size])
            self._cached_chunk = chunk[remaining_size:]

        return bytes(result_bytes)


class StreamingDecryptionBuffer(CustomBuffer):
    """Thread-safe buffer that decrypts data when reading."""

    def __init__(self) -> None:
        self._condition = threading.Condition()

        self._chunks: deque[bytes] = deque()
        self._download_finished = False

    def set_download_finished(self) -> None:
        with self._condition:
            self._download_finished = True

    def write(self, chunk: bytes) -> int:  # type: ignore
        with self._condition:
            self._condition.wait_for(
                lambda: self._get_cache_size() < DOWNLOAD_MEMORY_LIMIT_BYTES,
                timeout=DOWNLOAD_BUFFER_TIMEOUT_SEC,
            )
            self._chunks.append(chunk)
            self._condition.notify()
            return len(chunk)

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            raise ValueError("Reading the whole buffer is not supported")

        with self._condition:
            result_bytes = bytearray()

            while len(result_bytes) < size:
                self._condition.wait_for(
                    lambda: self._chunks or self._download_finished,
                    timeout=DOWNLOAD_BUFFER_TIMEOUT_SEC,
                )

                try:
                    chunk = self._chunks.popleft()
                except IndexError:
                    chunk = b""

                if not chunk and self._download_finished:
                    break

                remaining_size = size - len(result_bytes)
                result_bytes.extend(chunk[:remaining_size])
                if len(chunk) > remaining_size:
                    self._chunks.appendleft(chunk[remaining_size:])

                self._condition.notify()

            return bytes(result_bytes)

    def _get_cache_size(self) -> int:
        return reduce(lambda acc, chunk: acc + len(chunk), self._chunks, 0)
