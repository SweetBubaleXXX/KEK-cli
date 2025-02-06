import functools
import json
from io import BytesIO

import pytest
from gnukek.constants import SerializedKeyType

from gnukek_cli.command_handlers.import_keys import ImportKeysContext, ImportKeysHandler
from gnukek_cli.constants import CONFIG_FILENAME
from gnukek_cli.keys import get_private_key_filename, get_public_key_filename
from tests.constants import (
    ENCRYPTED_KEY_BATCH,
    ENCRYPTED_PRIVATE_KEY,
    KEY_ENCRYPTION_PASSWORD,
    KEY_ID,
    SERIALIZED_PRIVATE_KEY,
    SERIALIZED_PUBLIC_KEY,
)


@pytest.fixture()
def create_handler(key_provider, password_prompt_mock):
    return functools.partial(
        ImportKeysHandler,
        key_provider=key_provider,
        password_prompt=password_prompt_mock,
    )


@pytest.mark.parametrize(
    "context, key_type",
    [
        (
            ImportKeysContext([BytesIO(SERIALIZED_PRIVATE_KEY)]),
            SerializedKeyType.PRIVATE_KEY,
        ),
        (
            ImportKeysContext([BytesIO(ENCRYPTED_PRIVATE_KEY)]),
            SerializedKeyType.ENCRYPTED_PRIVATE_KEY,
        ),
        (
            ImportKeysContext([BytesIO(SERIALIZED_PUBLIC_KEY)]),
            SerializedKeyType.PUBLIC_KEY,
        ),
    ],
)
def test_import_single_key(
    context,
    key_type,
    create_handler,
    password_prompt_mock,
    storage_dir,
):
    if context.prompt_password:
        password_prompt_mock.get_password.return_value = KEY_ENCRYPTION_PASSWORD

    handle = create_handler(context)
    handle()

    if context.prompt_password and key_type == SerializedKeyType.ENCRYPTED_PRIVATE_KEY:
        password_prompt_mock.get_password.assert_called_once()
    else:
        password_prompt_mock.get_password.assert_not_called()

    config_path = storage_dir / CONFIG_FILENAME
    with open(config_path, "r") as config_file:
        settings = json.load(config_file)

    public_key_path = storage_dir / get_public_key_filename(KEY_ID)
    assert public_key_path.exists()
    assert settings["public"] == [KEY_ID]

    if key_type in (
        SerializedKeyType.PRIVATE_KEY,
        SerializedKeyType.ENCRYPTED_PRIVATE_KEY,
    ):
        private_key_path = storage_dir / get_private_key_filename(KEY_ID)
        assert private_key_path.exists()
        assert settings["default"] == KEY_ID
        assert settings["private"] == [KEY_ID]


def test_import_multiple_keys(create_handler, password_prompt_mock, storage_dir):
    password_prompt_mock.get_password.side_effect = [
        password for _, password in ENCRYPTED_KEY_BATCH
    ]

    context = ImportKeysContext(
        key_files=[BytesIO(key) for key, _ in ENCRYPTED_KEY_BATCH]
    )
    handle = create_handler(context)
    handle()

    assert password_prompt_mock.get_password.call_count == len(ENCRYPTED_KEY_BATCH)

    config_path = storage_dir / CONFIG_FILENAME
    with open(config_path, "r") as config_file:
        settings = json.load(config_file)

    assert len(settings["private"]) == len(ENCRYPTED_KEY_BATCH)
    assert len(settings["public"]) == len(ENCRYPTED_KEY_BATCH)
