from abc import ABCMeta, abstractmethod
from pathlib import Path
from typing import Annotated

from pydantic import constr
from pydantic_settings import BaseSettings, SettingsConfigDict

PrivateKeyId = Annotated[str, constr(pattern=r"\w{16}", to_lower=True)]
PublicKeyId = Annotated[str, constr(pattern=r"\w{16}.pub", to_lower=True)]


class Settings(BaseSettings):
    default: PrivateKeyId | None = None
    public: list[PublicKeyId] = []
    private: list[PrivateKeyId] = []

    model_config = SettingsConfigDict()


class SettingsProvider(metaclass=ABCMeta):
    @abstractmethod
    def get_settings(self) -> Settings: ...

    @abstractmethod
    def save_settings(self, settings: Settings) -> None: ...


class JsonSettingsProvider(SettingsProvider):
    indent = 2

    _settings: Settings | None = None

    def __init__(self, settings_path: str | Path) -> None:
        self._settings_path = Path(settings_path)

    def get_settings(self) -> Settings:
        if self._settings:
            return self._settings.model_copy()

        if not self._settings_path.exists():
            return Settings()

        with open(self._settings_path, "rb") as settings_file:
            raw_content = settings_file.read()

        self._settings = Settings.model_validate_json(raw_content)
        return self._settings

    def save_settings(self, settings: Settings) -> None:
        self._settings = settings

        with open(self._settings_path, "w") as settings_file:
            raw_content = settings.model_dump_json(indent=self.indent)
            settings_file.write(raw_content)
