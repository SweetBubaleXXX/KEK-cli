from typing import BinaryIO

from dependency_injector.wiring import Provide, inject

from gnukek_cli.config import SettingsProvider
from gnukek_cli.container import Container


class ListKeysHandler:
    @inject
    def __init__(
        self,
        *,
        settings_provider: SettingsProvider = Provide[Container.settings_provider],
        output_buffer: BinaryIO = Provide[Container.output_buffer],
    ) -> None:
        self._settings_provider = settings_provider
        self._output_buffer = output_buffer

    def __call__(self) -> None:
        settings = self._settings_provider.get_settings()

        default_key = settings.default or "null"
        self._output_buffer.write(f"default key: {default_key}\n".encode())

        self._output_buffer.write(b"private:\n")
        if settings.private:
            for key_id in settings.private:
                self._output_buffer.write(f"  - {key_id}\n".encode())
        else:
            self._output_buffer.write(b"  no keys\n")

        self._output_buffer.write(b"public:\n")
        if settings.public:
            for key_id in settings.public:
                self._output_buffer.write(f"  - {key_id}\n".encode())
        else:
            self._output_buffer.write(b"  no keys\n")
