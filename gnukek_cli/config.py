import logging
from abc import ABCMeta, abstractmethod
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, constr

from gnukek_cli.constants import CONFIG_DIR_PERMISSIONS, CONFIG_FILE_ENCODING

KeyId = Annotated[str, constr(pattern=r"\w{16}", to_lower=True)]

logger = logging.getLogger(__name__)


class Settings(BaseModel):
    default: KeyId | None = None
    public: list[KeyId] = []
    private: list[KeyId] = []


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
        logger.debug(
            f"Initialized JsonSettingsProvider with path: {self._settings_path}"
        )

    def load(self) -> Settings:
        if self._settings_path.exists():
            logger.debug(f"Loading settings from {self._settings_path}")
            raw_content = self._settings_path.read_text(encoding=CONFIG_FILE_ENCODING)
            self._settings = Settings.model_validate_json(raw_content)
        else:
            logger.debug(f"Settings file {self._settings_path} does not exist")
            self._settings = Settings()
        return self._settings

    def get_settings(self) -> Settings:
        if self._settings:
            logger.debug("Returning cached settings")
            return self._settings.model_copy()

        return self.load()

    def save_settings(self, settings: Settings) -> None:
        self._settings = settings
        logger.debug(f"Saving settings to {self._settings_path}")

        if not self._settings_path.parent.exists():
            logger.debug(f"Creating directory {self._settings_path.parent}")
            self._settings_path.parent.mkdir(CONFIG_DIR_PERMISSIONS)

        with open(
            self._settings_path, "w", encoding=CONFIG_FILE_ENCODING
        ) as settings_file:
            raw_content = settings.model_dump_json(indent=self.indent)
            settings_file.write(raw_content)
            logger.debug(f"Settings saved to {self._settings_path}")
