import json
import logging
import os
import random
from typing import Optional, Union

from KEK import exceptions
from KEK.hybrid import PrivateKEK, PublicKEK


class BaseFile:
    def __init__(self, path: str) -> None:
        if os.path.isdir(path):
            raise IsADirectoryError("Can't open file because it's a directory")
        self._path = path
        self._parent_folder, self._filename = os.path.split(path)

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

    def read(self, number_of_bytes: Optional[int] = None) -> bytes:
        with open(self._path, "rb") as file:
            return file.read(number_of_bytes)

    def write(self, byte_data: bytes) -> int:
        with open(self._path, "wb") as file:
            return file.write(byte_data)


class KeyFile(BaseFile):
    def __init__(self, path: str) -> None:
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
    def __init__(self, path: str, overwritable=False) -> None:
        super().__init__(path)
        self.overwritable = overwritable

    @property
    def output_filename(self) -> str:
        return f"{self._filename}.kek"

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
    def __init__(self, path: str, overwritable=False) -> None:
        super().__init__(path, overwritable)

    @property
    def output_filename(self) -> str:
        if len(self._filename) > 4 and self._filename.endswith(".kek"):
            return self._filename[:-4]
        return self._filename

    def decrypt(self, key_object: PrivateKEK) -> bytes:
        return key_object.decrypt(self.read())


class SignatureFile(File):
    def __init__(self, path: str, overwritable=False) -> None:
        super().__init__(path, overwritable)

    def verify(
        self,
        key_object: Union[PrivateKEK, PublicKEK],
        original_data: bytes
    ) -> bool:
        return key_object.verify(self.read(), original_data)


class KeyStorage:
    directory_permissions = 0o700
    key_file_permissions = 0o600
    config_filename = "config.json"
    password_encoding = "ascii"

    def __init__(self, location: str) -> None:
        if not os.path.isabs(location):
            raise ValueError(
                "Invalid storage location. Must be absolute path."
            )
        self._location = location
        self._config_path: os.path.join(self._location, self.config_filename)
        self._default_key: Union[str, None] = None
        self._private_keys = set()
        self._public_keys = set()
        self._key_objects = {}
        self.__load_directory()

    def __load_directory(self) -> None:
        if not os.path.isdir(self._location):
            os.mkdir(self._location)
            os.chmod(self._location, self.directory_permissions)
        self.__load_config()

    def __load_config(self) -> None:
        config = {}
        if os.path.isfile(self._config_path):
            with open(self._config_path, "r") as config_file:
                config = json.load(config_file)
        self._default_key = config.get("default", None)
        self._private_keys = set(config.get("private", []))
        self._public_keys = set(config.get("public", []))

    def __write_config(self) -> None:
        with open(self._config_path, "w") as config_file:
            json.dump({
                "default": self._default_key,
                "private": list(self._private_keys),
                "public": list(self._public_keys)
            }, config_file, indent=2)
            logging.debug("Config file written")

    def __add_public_key(self, key_object: PublicKEK, key_id: str) -> str:
        key_id = "".join((key_id, ".pub"))
        self._public_keys.add(key_id)
        self.__write_key(key_id, key_object.serialize())
        return key_id

    def __add_private_key(
        self,
        key_object: PrivateKEK,
        key_id: str,
        password: Optional[str] = None,
    ):
        self._private_keys.add(key_id)
        self._default_key = self._default_key or key_id
        encoded_password = self.encode_password(password)
        self.__write_key(key_id, key_object.serialize(encoded_password))

    def __load_key(
        self,
        key_id: str,
        password: Optional[str] = None
    ) -> Union[PrivateKEK, PublicKEK]:
        key_file = self.__read_key(key_id)
        return key_file.load(self.encode_password(password))

    def __read_key(self, key_id: str) -> KeyFile:
        key_path = self.__get_key_path(key_id)
        if not os.path.isfile(key_path):
            raise FileNotFoundError(f"Key '{key_id}' not found")
        return KeyFile(key_path)

    def __write_key(self, key_id: str, serialized_bytes: bytes) -> None:
        key_path = self.__get_key_path(key_id)
        key_file = KeyFile(key_path)
        key_file.write(serialized_bytes)

    def __get_key_path(self, key_id: str) -> str:
        return os.path.join(self._location, f"{key_id}.kek")

    def __decode_key_id(self, byte_id: bytes) -> str:
        return byte_id.hex()

    @property
    def default_key(self) -> Union[str, None]:
        if not self._default_key:
            logging.debug("No default key")
        return self._default_key

    @default_key.setter
    def default_key(self, key_id: Union[str, None]):
        if key_id not in self._private_keys:
            raise ValueError("No such private key")
        self._default_key = key_id

    @classmethod
    def encode_password(
        cls,
        password: Union[str, None]
    ) -> Union[bytes, None]:
        if password is not None:
            return password.encode(cls.password_encoding)
        return password

    def add(
        self,
        key_object: Union[PrivateKEK, PublicKEK],
        password: Optional[str] = None
    ) -> str:
        key_id = self.__decode_key_id(key_object.key_id)
        if isinstance(key_object, PublicKEK):
            key_id = self.__add_public_key(key_object, key_id)
        else:
            self.__add_private_key(key_object, key_id, password)
        self._key_objects[key_id] = key_object
        self.__write_config()
        return key_id

    def get(
        self,
        key_id: Optional[str] = None,
        password: Optional[str] = None
    ) -> Union[PrivateKEK, PublicKEK]:
        key_id = key_id or self.default_key
        all_keys = self._private_keys.union(self._public_keys)
        if not key_id and key_id not in all_keys:
            raise ValueError("Key not found")
        if key_id not in self._key_objects:
            key_object = self.__load_key(key_id, password)
            self._key_objects[key_id] = key_object
        return self._key_objects[key_id]


class KeyManager:
    KEK_version = PrivateKEK.version
    KEK_algorithm = PrivateKEK.algorithm
    KEK_key_sizes = PrivateKEK.key_sizes
    KEK_default_size = PrivateKEK.default_size
    default_storage_location = "~/.kek"

    def __init__(
        self,
        storage_location: Optional[str] = None,
        work_dir: Optional[str] = None
    ) -> None:
        self.storage_location = os.path.expanduser(
            storage_location
            or self.default_storage_location
        )
        self.key_storage = KeyStorage(self.storage_location)
        self.work_dir = work_dir or os.getcwd()

    def get_full_path(self, *paths: str) -> str:
        return os.path.abspath(
            os.path.expanduser(
                os.path.join(self.work_dir, *paths)
            )
        )

    def __read_file(self, path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read()

    def __write_file(
        self,
        path: str, byte_data: bytes,
        overwrite: bool = False
    ) -> None:
        if not overwrite and os.path.isfile(path):
            raise FileExistsError("File exists")
        with open(path, "wb") as f:
            f.write(byte_data)

    def is_encrypted(self, key_id: Optional[str] = None,
                     path: Optional[str] = None) -> bool:
        pass

    def set_default(self, key_id: str) -> None:
        pass

    def delete_key(self, key_id: str) -> None:
        """Try to delete key file and remove id from config."""
        if key_id not in self.private_keys.union(self.public_keys):
            raise FileNotFoundError("Key not found")
        try:
            os.remove(self.__get_key_path(key_id))
        except OSError:
            logging.debug("Key file not found")
        if key_id.endswith(".pub"):
            self.public_keys.remove(key_id)
        else:
            self.private_keys.remove(key_id)
            if key_id == self.default_key:
                default_key_id = random.choice(
                    list(self.private_keys) or [None])
                self.default_key = default_key_id
                logging.debug(f"New default key id: {default_key_id}")
        self.__write_config()

    def generate(self, key_size: int, password: Optional[str] = None) -> str:
        key = PrivateKEK.generate(key_size)
        return self.key_storage.add(key, password)

    def encrypt(
        self,
        file: str,
        output_file: Optional[str] = None,
        key_id: Optional[str] = None,
        password: Optional[str] = None,
        overwrite: bool = False
    ) -> str:
        key = self.key_storage.get(key_id, password)
        file_path = self.get_full_path(file)
        encrypted_bytes = key.encrypt(self.__read_file(file_path))
        default_filename = f"{file_path}.kek"
        output_path = self.get_full_path(output_file or default_filename)
        if os.path.isdir(output_path):
            output_path = os.path.join(output_path, default_filename)
        self.__write_file(output_path, encrypted_bytes, overwrite)
        return output_path

    def decrypt(self,
                file: str,
                output_file: Optional[str] = None,
                key_id: Optional[str] = None,
                password: Optional[str] = None,
                overwrite: bool = False,
                work_dir: Optional[str] = None) -> str:
        """Decrypt and write file."""
        file_path = self.get_full_path(file, work_dir)
        key = self.__load_private_key(
            self.__read_key(
                self.__get_key_path(key_id or self.default_key)), password)
        decrypted_bytes = key.decrypt(self.__read_file(file_path))
        default_filename = file.endswith(".kek") and file[:-4] or file
        output_path = self.get_full_path(output_file or default_filename,
                                         work_dir)
        if os.path.isdir(output_path):
            output_path = os.path.join(output_path, default_filename)
        self.__write_file(output_path, decrypted_bytes, overwrite)
        return output_path

    def sign(self,
             file: str,
             output_file: Optional[str] = None,
             key_id: Optional[str] = None,
             password: Optional[str] = None,
             overwrite: bool = False,
             work_dir: Optional[str] = None) -> str:
        """Sign and write file."""
        file_path = self.get_full_path(file, work_dir)
        key = self.__load_private_key(
            self.__read_key(
                self.__get_key_path(key_id or self.default_key)), password)
        signature_bytes = key.sign(self.__read_file(file_path))
        default_filename = f"{file}.kek"
        output_path = self.get_full_path(output_file or default_filename,
                                         work_dir)
        if os.path.isdir(output_path):
            output_path = os.path.join(output_path, default_filename)
        self.__write_file(output_path,
                          signature_bytes.hex().encode(self.encoding),
                          overwrite)
        return output_path

    def verify(self,
               signature_file: str,
               file: str,
               key_id: Optional[str] = None,
               password: Optional[str] = None,
               work_dir: Optional[str] = None) -> bool:
        """Verify signature."""
        file_path = self.get_full_path(file, work_dir)
        signature_path = self.get_full_path(signature_file, work_dir)
        key = self.__load_key_by_id(key_id, password)
        signature_bytes = bytes.fromhex(
            self.__read_file(signature_path).decode(self.encoding).strip())
        file_bytes = self.__read_file(file_path)
        return key.verify(signature_bytes, file_bytes)

    def import_key(self, file: str, password: Optional[str] = None,
                   work_dir: Optional[str] = None) -> str:
        """Import key from file and save it to home directory."""
        path = self.get_full_path(file, work_dir)
        try:
            key = self.__load_private_key(self.__read_key(path), password)
            key_id = self.__decode_key_id(key.key_id)
            self.private_keys.add(key_id)
            if not self.default_key:
                self.default_key = key_id
            self.__save_key_to_file(self.__get_key_path(key_id), key, password)
        except exceptions.KeyLoadingError:
            key = self.__load_public_key(self.__read_key(path))
            key_id = f"{self.__decode_key_id(key.key_id)}.pub"
            self.public_keys.add(key_id)
            self.__save_key_to_file(self.__get_key_path(key_id), key)
        finally:
            self.__write_config()
            return key_id

    def export_key(self,
                   id: str,
                   public: Optional[bool] = False,
                   output_file: Optional[str] = None,
                   password: Optional[str] = None,
                   overwrite: bool = False,
                   work_dir: Optional[str] = None) -> None:
        """Export key to file."""
        output_path = self.get_full_path(output_file or f"{id}.kek", work_dir)
        if id.endswith(".pub"):
            for key_id in self.public_keys:
                if key_id != id:
                    continue
                key_bytes = self.__read_key(self.__get_key_path(id))
                key_obj = self.__load_public_key(key_bytes)
                return self.__save_key_to_file(output_path, key_obj,
                                               overwrite=overwrite)
        else:
            for key_id in self.private_keys:
                if key_id != id:
                    continue
                key_bytes = self.__read_key(self.__get_key_path(id))
                key_obj = self.__load_private_key(key_bytes, password)
                if public:
                    output_path = self.get_full_path(output_file or
                                                     f"{id}.pub.kek", work_dir)
                    return self.__save_key_to_file(output_path,
                                                   key_obj.public_key,
                                                   overwrite=overwrite)
                return self.__save_key_to_file(output_path, key_obj,
                                               password, overwrite)
