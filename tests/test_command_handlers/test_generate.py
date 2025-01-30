import functools
import io
import json

import pytest
from gnukek.constants import SerializedKeyType
from gnukek.utils import get_key_type

from gnukek_cli.command_handlers.generate import GenerateKeyContext, GenerateKeyHandler
from gnukek_cli.constants import CONFIG_FILENAME
from gnukek_cli.helpers import get_public_key_id
from gnukek_cli.keys import get_private_key_filename, get_public_key_filename


@pytest.fixture()
def output_buffer():
    return io.BytesIO()


@pytest.fixture
def create_handler(
    public_key_file_storage,
    private_key_file_storage,
    settings_provider,
    password_prompt_mock,
    output_buffer,
):
    return functools.partial(
        GenerateKeyHandler,
        public_key_storage=public_key_file_storage,
        private_key_storage=private_key_file_storage,
        settings_provider=settings_provider,
        password_prompt=password_prompt_mock,
        output_buffer=output_buffer,
    )


@pytest.mark.parametrize(
    "context, expected_private_key_type",
    [
        (
            GenerateKeyContext(key_size=2048, prompt_password=False),
            SerializedKeyType.PRIVATE_KEY,
        ),
        (
            GenerateKeyContext(key_size=2048, prompt_password=True),
            SerializedKeyType.ENCRYPTED_PRIVATE_KEY,
        ),
        (
            GenerateKeyContext(
                key_size=2048, password=b"password", prompt_password=False
            ),
            SerializedKeyType.ENCRYPTED_PRIVATE_KEY,
        ),
    ],
)
def test_generate_key(
    create_handler,
    storage_dir,
    password_prompt_mock,
    context,
    expected_private_key_type,
):
    if context.prompt_password:
        password_prompt_mock.create_password.return_value = b"password"

    handle = create_handler(context)
    handle()

    if context.prompt_password:
        password_prompt_mock.create_password.assert_called_once()
    else:
        password_prompt_mock.create_password.assert_not_called()

    config_path = storage_dir / CONFIG_FILENAME
    with open(config_path, "r") as config_file:
        settings = json.load(config_file)

    key_id = settings["default"]
    assert key_id in settings["private"]
    assert get_public_key_id(key_id) in settings["public"]

    private_key_path = storage_dir / get_private_key_filename(key_id)
    with open(private_key_path, "rb") as private_key_file:
        private_key = private_key_file.read()
        assert get_key_type(private_key) == expected_private_key_type

    public_key_path = storage_dir / get_public_key_filename(key_id)
    with open(public_key_path, "rb") as public_key_file:
        public_key = public_key_file.read()
        assert get_key_type(public_key) == SerializedKeyType.PUBLIC_KEY


def test_generate_key_no_save(create_handler, output_buffer):
    handle = create_handler(GenerateKeyContext(prompt_password=False, save=False))
    handle()

    written_to_buffer = output_buffer.getvalue()
    key_type = get_key_type(written_to_buffer)
    assert key_type == SerializedKeyType.PRIVATE_KEY
