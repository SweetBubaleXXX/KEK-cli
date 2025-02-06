from abc import ABCMeta, abstractmethod
from pathlib import Path
from typing import Annotated

from pydantic import constr
from pydantic_settings import BaseSettings, SettingsConfigDict

KeyId = Annotated[str, constr(pattern=r"\w{16}", to_lower=True)]


class Settings(BaseSettings):
    default: KeyId | None = None
    public: list[KeyId] = []
    private: list[KeyId] = []

    model_config = SettingsConfigDict()


class SettingsProvider(metaclass=ABCMeta):
    @abstractmethod
    def load(self) -> Settings: ...

    @abstractmethod
    def get_settings(self) -> Settings: ...

    @abstractmethod
    def save_settings(self, settings: Settings) -> None: ...


class JsonSettingsProvider(SettingsProvider):
    indent = 2

    _settings: Settings | None = None

    def __init__(self, settings_path: str | Path) -> None:
        self._settings_path = Path(settings_path)

    def load(self) -> Settings:
        if self._settings_path.exists():
            raw_content = self._settings_path.read_bytes()
            self._settings = Settings.model_validate_json(raw_content)
        else:
            self._settings = Settings()
        return self._settings

    def get_settings(self) -> Settings:
        if self._settings:
            return self._settings.model_copy()

        return self.load()

    def save_settings(self, settings: Settings) -> None:
        self._settings = settings

        with open(self._settings_path, "w") as settings_file:
            raw_content = settings.model_dump_json(indent=self.indent)
            settings_file.write(raw_content)
