import json
import logging
import os
from typing import Optional, Union

from KEK import exceptions
from KEK.hybrid import PrivateKEK, PublicKEK

from .get_full_path import get_full_path


class KeyManager:
    def __init__(self) -> None:
        self.__load_kek_dir()

    def __load_kek_dir(self) -> None:
        home_dir = os.path.expanduser("~")
        self.kek_dir = os.path.join(home_dir, ".kek")
        if not os.path.isdir(self.kek_dir):
            os.mkdir(self.kek_dir)
        self.__load_config()

    def __load_config(self) -> None:
        self.config_path = os.path.join(self.kek_dir, "config.json")
        config = {}
        if os.path.isfile(self.config_path):
            with open(self.config_path, "r") as f:
                config = json.load(f)
        self.default_key = config.get("default", None)
        self.private_keys = set(config.get("private", []))
        self.public_keys = set(config.get("public", []))

    def __write_config(self) -> None:
        with open(self.config_path, "w") as f:
            json.dump({
                "default": self.default_key,
                "private": list(self.private_keys),
                "public": list(self.public_keys)
            }, f, indent=2)

    def __get_key_path(self, id: str) -> str:
        return get_full_path(f"{id}.kek", self.kek_dir)

    def __save_key_to_file(self, path: str,
                           key_obj: Union[PrivateKEK, PublicKEK],
                           password: Optional[str] = None) -> None:
        if password:
            self.__write_key(
                path, key_obj.serialize(self.__encode_password(password)))
        else:
            self.__write_key(path, key_obj.serialize())

    def __read_key(self, path: str) -> bytes:
        if not os.path.isfile(path):
            logging.error("Key not found")
        with open(path, "r") as f:
            return f.read().encode("ascii")

    def __write_key(self, path: str, serialized_bytes: bytes) -> None:
        with open(path, "w") as f:
            f.write(serialized_bytes.decode("ascii"))

    def __read_file(self, path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read()

    def __write_file(self, path: str, byte_data: bytes) -> None:
        with open(path, "wb") as f:
            f.write(byte_data)

    def __load_private_key(self, serialized_bytes: bytes,
                           password: Optional[str] = None) -> PrivateKEK:
        return PrivateKEK.load(serialized_bytes,
                               self.__encode_password(password))

    def __load_public_key(self, serialized_bytes: bytes) -> PublicKEK:
        return PublicKEK.load(serialized_bytes)

    def __decode_key_id(self, byte_id: bytes) -> str:
        return byte_id.hex()

    def __encode_password(self,
                          password: Union[str, None]) -> Union[bytes, None]:
        if password is not None:
            return password.encode("ascii")
        return password

    def is_encrypted(self, key_id: Optional[str] = None,
                     path: Optional[str] = None) -> bool:
        if key_id and key_id.endswith(".pub"):
            return False
        key = self.__read_key(path or
                              self.__get_key_path(key_id or self.default_key))
        if key.splitlines()[0] == b"-----BEGIN ENCRYPTED PRIVATE KEY-----":
            return True
        return False

    def set_default(self, key_id: str) -> None:
        if key_id in self.private_keys:
            self.default_key = key_id
            self.__write_config()
        else:
            logging.error("No such private key")

    def generate(self, key_size: int, password: Optional[str] = None) -> str:
        key = PrivateKEK.generate(key_size)
        key_id = self.__decode_key_id(key.key_id)
        self.private_keys.add(key_id)
        if not self.default_key:
            self.default_key = key_id
        self.__save_key_to_file(self.__get_key_path(key_id),
                                key, password)
        self.__write_config()
        return key_id

    def encrypt(self, file: str, output_file: Optional[str] = None,
                key_id: Optional[str] = None, password: Optional[str] = None,
                work_dir: Optional[str] = None) -> str:
        file_path = get_full_path(file, work_dir)
        if key_id and key_id.endswith(".pub"):
            key = self.__load_public_key(
                self.__read_key(self.__get_key_path(key_id)))
        else:
            key = self.__load_private_key(
                self.__read_key(
                    self.__get_key_path(key_id or self.default_key)), password)
        encrypted_bytes = key.encrypt(self.__read_file(file_path))
        default_filename = f"{file}.kek"
        output_path = get_full_path(output_file or default_filename, work_dir)
        if os.path.isdir(output_path):
            output_path = os.path.join(output_path, default_filename)
        self.__write_file(output_path, encrypted_bytes)
        return output_path

    def decrypt(self, file: str, output_file: Optional[str] = None,
                key_id: Optional[str] = None, password: Optional[str] = None,
                work_dir: Optional[str] = None) -> str:
        file_path = get_full_path(file, work_dir)
        key = self.__load_private_key(
            self.__read_key(
                self.__get_key_path(key_id or self.default_key)), password)
        decrypted_bytes = key.decrypt(self.__read_file(file_path))
        default_filename = file.endswith(".kek") and file[:-4] or file
        output_path = get_full_path(output_file or default_filename, work_dir)
        if os.path.isdir(output_path):
            output_path = os.path.join(output_path, default_filename)
        self.__write_file(output_path, decrypted_bytes)
        return output_path

    def sign(self):
        pass

    def verify(self):
        pass

    def import_key(self, file: str, password: Optional[str] = None,
                   work_dir: Optional[str] = None) -> str:
        path = get_full_path(file, work_dir)
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

    def export_key(self, id: str, public: Optional[bool] = False,
                   output_file: Optional[str] = None,
                   password: Optional[str] = None,
                   work_dir: Optional[str] = None) -> None:
        output_path = get_full_path(output_file or f"{id}.kek", work_dir)
        if id.endswith(".pub"):
            for key_id in self.public_keys:
                if key_id != id:
                    continue
                key_bytes = self.__read_key(self.__get_key_path(id))
                key_obj = self.__load_public_key(key_bytes)
                return self.__save_key_to_file(output_path, key_obj)
        else:
            for key_id in self.private_keys:
                if key_id != id:
                    continue
                key_bytes = self.__read_key(self.__get_key_path(id))
                key_obj = self.__load_private_key(key_bytes, password)
                if public:
                    output_path = get_full_path(output_file or f"{id}.pub.kek",
                                                work_dir)
                    return self.__save_key_to_file(output_path,
                                                   key_obj.public_key)
                return self.__save_key_to_file(output_path, key_obj, password)
