from typing import BinaryIO

from dependency_injector.wiring import Provide, inject
from gnukek.constants import LATEST_KEK_VERSION, SUPPORTED_KEY_SIZES

from gnukek_cli import __version__
from gnukek_cli.container import Container


class VersionHandler:
    @inject
    def __init__(
        self,
        *,
        key_storage_path: str = Provide[Container.config.key_storage_path],
        output_buffer: BinaryIO = Provide[Container.output_buffer],
    ) -> None:
        self._key_storage_path = key_storage_path
        self._output_buffer = output_buffer

    def __call__(self) -> None:
        self._output_buffer.write(f"gnukek-cli {__version__}\n\n".encode())
        self._output_buffer.write(
            f"Latest KEK algorithm supported: {LATEST_KEK_VERSION}\n".encode()
        )
        self._output_buffer.write(f"Config path: {self._key_storage_path}\n".encode())

        supported_key_sizes = map(str, sorted(SUPPORTED_KEY_SIZES))
        self._output_buffer.write(
            f"Supported key sizes: {', '.join(supported_key_sizes)}\n".encode()
        )
