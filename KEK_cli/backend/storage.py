import json
import logging
import os
import random
from typing import Dict, List, Optional, Set, Union

from KEK.hybrid import PrivateKEK, PublicKEK

from .files import KeyFile


class KeyStorage:
    directory_permissions = 0o700
    key_file_permissions = 0o600
    config_filename = "config.json"
    password_encoding = "ascii"

    def __init__(self, location: str):
        if not os.path.isabs(location):
            raise ValueError(
                "Invalid storage location. Must be absolute path."
            )
        self._location = location
        self._config_path = os.path.join(self._location, self.config_filename)
        self._default_key: Optional[str] = None
        self._private_keys: Set[str] = set()
        self._public_keys: Set[str] = set()
        self._key_objects: Dict[str, Union[PrivateKEK, PublicKEK]] = {}
        self.__load_directory()

    def __contains__(self, key_id: str) -> bool:
        all_keys = self._private_keys.union(self._public_keys)
        return key_id in all_keys

    @property
    def config_path(self) -> str:
        return self._config_path

    @property
    def default_key(self) -> Optional[str]:
        if not self._default_key:
            logging.debug("No default key")
        return self._default_key

    @default_key.setter
    def default_key(self, key_id: Optional[str]):
        if key_id not in self._private_keys:
            raise ValueError("No such private key")
        self._default_key = key_id
        self.__write_config()

    @property
    def private_keys(self) -> List[str]:
        return sorted(self._private_keys)

    @property
    def public_keys(self) -> List[str]:
        return sorted(self._public_keys)

    def __load_directory(self):
        if not os.path.isdir(self._location):
            os.mkdir(self._location)
            os.chmod(self._location, self.directory_permissions)
        self.__load_config()

    def __load_config(self):
        config = {}
        if os.path.isfile(self._config_path):
            with open(self._config_path, "r") as config_file:
                config = json.load(config_file)
        self._default_key = config.get("default", None)
        self._private_keys = set(config.get("private", []))
        self._public_keys = set(config.get("public", []))

    def __write_config(self):
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

    def __write_key(self, key_id: str, serialized_bytes: bytes):
        key_path = self.__get_key_path(key_id)
        key_file = KeyFile(key_path)
        key_file.write(serialized_bytes)
        os.chmod(key_file.path, self.key_file_permissions)

    def __get_key_path(self, key_id: str) -> str:
        return os.path.join(self._location, f"{key_id}.kek")

    def __decode_key_id(self, byte_id: bytes) -> str:
        return byte_id.hex()

    @classmethod
    def encode_password(
        cls,
        password: Optional[str]
    ) -> Optional[bytes]:
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

    def remove(self, key_id: str):
        if key_id not in self:
            raise ValueError("Key not found")
        key_file = self.__read_key(key_id)
        try:
            key_file.delete()
        except OSError:
            logging.debug("Key file not found")
        if key_id.endswith(".pub"):
            self._public_keys.remove(key_id)
        else:
            self._private_keys.remove(key_id)
            if key_id == self.default_key:
                default_key_id = random.choice(
                    list(self._private_keys) or [None]
                )
                self._default_key = default_key_id
                logging.debug("New default key id: %s", default_key_id)
        self.__write_config()

    def get(
        self,
        key_id: Optional[str] = None,
        password: Optional[str] = None
    ) -> Union[PrivateKEK, PublicKEK]:
        if not key_id or key_id not in self:
            raise ValueError("Key not found")
        if key_id not in self._key_objects:
            key_object = self.__load_key(key_id, password)
            self._key_objects[key_id] = key_object
        return self._key_objects[key_id]

    def export(self, key_id: Optional[str] = None) -> KeyFile:
        if not key_id:
            raise
        return self.__read_key(key_id)
