import json
import logging
import os
from os import path
from typing import Optional

from KEK import exceptions
from KEK.hybrid import PrivateKEK, PublicKEK


def get_full_path(file: str, work_dir: Optional[str] = None) -> str:
    if not work_dir:
        work_dir = os.getcwd()
    return path.abspath(path.join(work_dir, file))


class KeyBackend:
    def __init__(self) -> None:
        self.__load_kek_dir()

    def __load_config(self) -> None:
        self.config_path = path.join(self.kek_dir, "config.json")
        config = {}
        if path.isfile(self.config_path):
            with open(self.config_path, "r") as f:
                config = json.load(f)
        self.default_key = config.get("default", None)
        self.private_keys = set(config.get("private", []))
        self.public_keys = set(config.get("public", []))

    def __load_kek_dir(self) -> None:
        home_dir = path.expanduser("~")
        self.kek_dir = path.join(home_dir, ".kek")
        if not path.isdir(self.kek_dir):
            os.mkdir(self.kek_dir)
        self.__load_config()

    def __write_config(self) -> None:
        with open(self.config_path, "w") as f:
            json.dump({
                "default": self.default_key,
                "private": self.private_keys,
                "public": self.public_keys
            }, f)

    def __encode_key_id(self, byte_id: bytes) -> str:
        return byte_id.hex()

    def __read_key(self, path: str) -> bytes:
        with open(path, "r") as f:
            return f.read().encode("ascii")

    def generate(self, key_size: int) -> None:
        key = PrivateKEK.generate(key_size)
        key_id = self.__encode_key_id(key.key_id)
        self.private_keys.add(key_id)
        if not self.default_key:
            self.default_key = key_id

    def encrypt():
        pass

    def decrypt():
        pass

    def sign():
        pass

    def verify():
        pass

    def import_key(self, file: str, password: Optional[str] = None,
                   work_dir: Optional[str] = None) -> None:
        path = get_full_path(file, work_dir)
        try:
            key = PrivateKEK.load(self.__read_key(path), password)
            key_id = self.__encode_key_id(key.key_id)
            self.private_keys.add(key_id)
            if not self.default_key:
                self.default_key = key_id
        except exceptions.KeyLoadingError:
            key = PublicKEK.load(self.__read_key(path))
            key_id = self.__encode_key_id(key.key_id)
            self.public_keys.add(key_id)

    def export_key(self, id: str, output_file: Optional[str] = None,
                   password: Optional[str] = None,
                   work_dir: Optional[str] = None):
        path = get_full_path(output_file, work_dir)
