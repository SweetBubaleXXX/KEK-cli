import json
import logging
import os
import random
from typing import Optional, Union

from KEK import exceptions
from KEK.hybrid import PrivateKEK, PublicKEK

from .get_full_path import get_full_path


class KeyManager:
    def __init__(self) -> None:
        self.__load_kek_dir()

    @property
    def default_key(self) -> Union[str, None]:
        if not self._default_key:
            logging.debug("No default key")
        return self._default_key

    @default_key.setter
    def default_key(self, val: Union[str, None]):
        self._default_key = val

    def __load_kek_dir(self) -> None:
        home_dir = os.path.expanduser("~")
        self.kek_dir = os.path.join(home_dir, ".kek")
        if not os.path.isdir(self.kek_dir):
            os.mkdir(self.kek_dir)
            os.chmod(self.kek_dir, 0o700)
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

    def __get_key_path(self, id: Union[str, None]) -> str:
        if id is None:
            raise FileNotFoundError("Key not found")
        return get_full_path(f"{id}.kek", self.kek_dir)

    def __save_key_to_file(self, path: str,
                           key_obj: Union[PrivateKEK, PublicKEK],
                           password: Optional[str] = None,
                           overwrite: bool = True) -> None:
        if not overwrite and os.path.isfile(path):
            raise FileExistsError("File exists")
        if password:
            self.__write_key(
                path, key_obj.serialize(self.__encode_password(password)))
        else:
            self.__write_key(path, key_obj.serialize())
        os.chmod(path, 0o600)

    def __read_key(self, path: str) -> bytes:
        if not os.path.isfile(path):
            raise FileNotFoundError("Key not found")
        with open(path, "r") as f:
            return f.read().encode("ascii")

    def __write_key(self, path: str, serialized_bytes: bytes) -> None:
        with open(path, "w") as f:
            f.write(serialized_bytes.decode("ascii"))

    def __read_file(self, path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read()

    def __write_file(self, path: str, byte_data: bytes,
                     overwrite: bool = False) -> None:
        if not overwrite and os.path.isfile(path):
            raise FileExistsError("File exists")
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

    def delete_key(self, key_id: str) -> None:
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
        key_id = self.__decode_key_id(key.key_id)
        self.private_keys.add(key_id)
        if not self.default_key:
            self.default_key = key_id
        self.__save_key_to_file(self.__get_key_path(key_id),
                                key, password)
        self.__write_config()
        return key_id

    def encrypt(self,
                file: str,
                output_file: Optional[str] = None,
                key_id: Optional[str] = None,
                password: Optional[str] = None,
                overwrite: bool = False,
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
        self.__write_file(output_path, encrypted_bytes, overwrite)
        return output_path

    def decrypt(self,
                file: str,
                output_file: Optional[str] = None,
                key_id: Optional[str] = None,
                password: Optional[str] = None,
                overwrite: bool = False,
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
        self.__write_file(output_path, decrypted_bytes, overwrite)
        return output_path

    def sign(self,
             file: str,
             output_file: Optional[str] = None,
             key_id: Optional[str] = None,
             password: Optional[str] = None,
             overwrite: bool = False,
             work_dir: Optional[str] = None) -> str:
        file_path = get_full_path(file, work_dir)
        key = self.__load_private_key(
            self.__read_key(
                self.__get_key_path(key_id or self.default_key)), password)
        signature_bytes = key.sign(self.__read_file(file_path))
        default_filename = f"{file}.kek"
        output_path = get_full_path(output_file or default_filename, work_dir)
        if os.path.isdir(output_path):
            output_path = os.path.join(output_path, default_filename)
        self.__write_file(output_path, signature_bytes.hex().encode("ascii"),
                          overwrite)
        return output_path

    def verify(self,
               signature_file: str,
               file: str,
               key_id: Optional[str] = None,
               password: Optional[str] = None,
               work_dir: Optional[str] = None) -> bool:
        file_path = get_full_path(file, work_dir)
        signature_path = get_full_path(signature_file, work_dir)
        if key_id and key_id.endswith(".pub"):
            key = self.__load_public_key(
                self.__read_key(self.__get_key_path(key_id)))
        else:
            key = self.__load_private_key(
                self.__read_key(
                    self.__get_key_path(key_id or self.default_key)), password)
        signature_bytes = bytes.fromhex(
            self.__read_file(signature_path).decode("ascii").strip())
        file_bytes = self.__read_file(file_path)
        return key.verify(signature_bytes, file_bytes)

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

    def export_key(self,
                   id: str,
                   public: Optional[bool] = False,
                   output_file: Optional[str] = None,
                   password: Optional[str] = None,
                   overwrite: bool = False,
                   work_dir: Optional[str] = None) -> None:
        output_path = get_full_path(output_file or f"{id}.kek", work_dir)
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
                    output_path = get_full_path(output_file or f"{id}.pub.kek",
                                                work_dir)
                    return self.__save_key_to_file(output_path,
                                                   key_obj.public_key,
                                                   overwrite=overwrite)
                return self.__save_key_to_file(output_path, key_obj,
                                               password, overwrite)
