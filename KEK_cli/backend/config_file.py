import json
import logging
import os
from typing import Optional, Set


class ConfigFile:
    indent = 2

    def __init__(self, path: str):
        if not os.path.isabs(path):
            raise ValueError(
                "Invalid storage location. Must be absolute path."
            )
        self.path = path
        self._config = self.__read_config()
        self.default_key: Optional[str] = self._config.get("default", None)
        self.private_keys: Set[str] = set(self._config.get("private", []))
        self.public_keys: Set[str] = set(self._config.get("public", []))

    def __read_config(self) -> dict:
        if os.path.isfile(self.path):
            with open(self.path, "r") as config_file:
                return json.load(config_file)
        return {}

    def write(self):
        with open(self.path, "w") as config_file:
            json.dump({
                "default": self.default_key,
                "private": list(self.private_keys),
                "public": list(self.public_keys)
            }, config_file, indent=self.indent)
            logging.debug("Config file written")
