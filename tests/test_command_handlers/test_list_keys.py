import pytest

from gnukek_cli.command_handlers.list_keys import ListKeysHandler
from tests.constants import KEY_ID


@pytest.fixture()
def handle_command(settings_provider, output_buffer):
    return ListKeysHandler(
        settings_provider=settings_provider, output_buffer=output_buffer
    )


def test_list_keys_empty_config(handle_command, output_buffer):
    handle_command()

    buffer_content = output_buffer.getvalue()
    assert b"default key: null" in buffer_content
    assert buffer_content.count(b"no keys") == 2


@pytest.mark.usefixtures("settings_file")
def test_list_keys(handle_command, output_buffer):
    handle_command()

    buffer_content = output_buffer.getvalue()
    assert f"default key: {KEY_ID}".encode() in buffer_content
