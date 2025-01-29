from abc import ABCMeta, abstractmethod
from pathlib import Path
from typing import Annotated

from pydantic import constr
from pydantic_settings import BaseSettings, SettingsConfigDict

PrivateKeyId = Annotated[str, constr(pattern=r"\w{16}", to_lower=True)]
PublicKeyId = Annotated[str, constr(pattern=r"\w{16}.pub", to_lower=True)]


class Config(BaseSettings):
    default: PrivateKeyId | None = None
    public: list[PublicKeyId] = []
    private: list[PrivateKeyId] = []

    model_config = SettingsConfigDict()


class ConfigProvider(metaclass=ABCMeta):
    @abstractmethod
    def get_config(self) -> Config: ...

    @abstractmethod
    def save_config(self, config: Config) -> None: ...


class JsonConfigProvider(ConfigProvider):
    indent = 2

    _config: Config | None = None

    def __init__(self, config_path: str) -> None:
        self._config_path = Path(config_path)

    def get_config(self) -> Config:
        if self._config:
            return self._config.model_copy()

        with open(self._config_path, "rb") as config_file:
            raw_content = config_file.read()

        self._config = Config.model_validate_json(raw_content)
        return self._config

    def save_config(self, config: Config) -> None:
        self._config = config

        with open(self._config_path, "w") as config_file:
            raw_content = config.model_dump_json(indent=self.indent)
            config_file.write(raw_content)
