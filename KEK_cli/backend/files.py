from __future__ import annotations

import os
from contextlib import contextmanager
from typing import IO, Generator, Optional, Union

from KEK.hybrid import PrivateKEK, PublicKEK


class BaseFile:
    def __init__(self, path: str):
        if os.path.isdir(path):
            raise IsADirectoryError("Can't open file because it's a directory")
        self._path = path
        self._parent_folder, self._filename = os.path.split(path)

    def __eq__(self, __o: object) -> bool:
        if not isinstance(__o, BaseFile):
            return NotImplemented
        return self._path == __o._path

    @property
    def path(self) -> str:
        return self._path

    @property
    def parent_folder(self) -> str:
        return self._parent_folder

    @property
    def filename(self) -> str:
        return self._filename

    @property
    def exists(self) -> bool:
        return os.path.isfile(self._path)

    @contextmanager
    def open(self, mode: str) -> Generator[IO, None, None]:
        file = open(self._path, mode)
        try:
            yield file
        finally:
            file.close()

    def read(self, number_of_bytes: Optional[int] = None) -> bytes:
        with self.open("rb") as file:
            return file.read(number_of_bytes)

    def write(self, byte_data: bytes) -> int:
        with self.open("wb") as file:
            return file.write(byte_data)

    def delete(self):
        os.remove(self._path)


class KeyFile(BaseFile):
    def __init__(self, path: str):
        super().__init__(path)

    @property
    def is_encrypted(self) -> bool:
        return PrivateKEK.is_encrypted(self.read())

    @property
    def is_public(self) -> bool:
        return self.__is_public(self.read())

    def __is_public(self, serialized_key: bytes) -> bool:
        first_line = serialized_key.strip().splitlines()[0]
        return first_line == PublicKEK.first_line

    def load(
        self,
        password: Optional[bytes] = None
    ) -> Union[PrivateKEK, PublicKEK]:
        serialized_key = self.read()
        if self.__is_public(serialized_key):
            return PublicKEK.load(serialized_key)
        return PrivateKEK.load(serialized_key, password)

    def export(
        self,
        key_object: Union[PrivateKEK, PublicKEK],
        password: Optional[bytes] = None
    ) -> int:
        if isinstance(key_object, PublicKEK):
            serialized_key = key_object.serialize()
        else:
            serialized_key = key_object.serialize(password)
        return self.write(serialized_key)


class File(BaseFile):
    def __init__(self, path: str, overwritable=False):
        super().__init__(path)
        self.overwritable = overwritable

    @property
    def output_path(self) -> str:
        return f"{self._path}.kek"

    def write(self, byte_data: bytes) -> int:
        if not self.overwritable and self.exists:
            raise FileExistsError(
                "Can't write file because it is already exists"
            )
        return super().write(byte_data)

    def encrypt(self, key_object: Union[PrivateKEK, PublicKEK]) -> bytes:
        return key_object.encrypt(self.read())

    def sign(self, key_object: PrivateKEK) -> bytes:
        return key_object.sign(self.read())


class EncryptedFile(File):
    def __init__(self, path: str, overwritable=False):
        super().__init__(path, overwritable)

    @property
    def output_path(self) -> str:
        if len(self._filename) > 4 and self._filename.endswith(".kek"):
            return self._path[:-4]
        return self._path

    def decrypt(self, key_object: PrivateKEK) -> bytes:
        return key_object.decrypt(self.read())


class SignatureFile(File):
    def __init__(self, path: str, overwritable=False):
        super().__init__(path, overwritable)

    def verify(
        self,
        key_object: Union[PrivateKEK, PublicKEK],
        original_data: bytes
    ) -> bool:
        return key_object.verify(self.read(), original_data)
