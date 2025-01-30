import pytest

from gnukek_cli import __version__
from gnukek_cli.command_handlers.version import VersionHandler


@pytest.fixture()
def handle_command(storage_dir, output_buffer):
    return VersionHandler(key_storage_path=storage_dir, output_buffer=output_buffer)


def test_show_version_info(handle_command, output_buffer):
    handle_command()

    buffer_content = output_buffer.getvalue()
    assert __version__.encode() in buffer_content
