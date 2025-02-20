import functools
from io import BytesIO

import pytest

from gnukek_cli.command_handlers.export import ExportContext, ExportHandler
from tests.constants import (
    KEY_ENCRYPTION_PASSWORD,
    KEY_ID,
    SERIALIZED_PRIVATE_KEY,
    SERIALIZED_PUBLIC_KEY,
)
from tests.helpers import remove_public_keys_from_settings


@pytest.fixture()
def create_handler(
    public_key_file_storage,
    private_key_file_storage,
    settings_provider,
    password_prompt_mock,
):
    return functools.partial(
        ExportHandler,
        public_key_storage=public_key_file_storage,
        private_key_storage=private_key_file_storage,
        settings_provider=settings_provider,
        password_prompt=password_prompt_mock,
    )


@pytest.mark.usefixtures("saved_private_key", "settings_file")
def test_export_key(create_handler, password_prompt_mock):
    password_prompt_mock.create_password.return_value = b""
    output_file = BytesIO()

    handle = create_handler(ExportContext(key_id=KEY_ID, file=output_file))
    handle()

    password_prompt_mock.create_password.assert_called_once()
    assert output_file.getvalue() == SERIALIZED_PRIVATE_KEY


@pytest.mark.usefixtures("saved_private_key", "settings_file")
def test_export_key_without_password(create_handler, password_prompt_mock):
    output_file = BytesIO()

    handle = create_handler(
        ExportContext(key_id=KEY_ID, file=output_file, prompt_password=False)
    )
    handle()

    password_prompt_mock.create_password.assert_not_called()
    assert output_file.getvalue() == SERIALIZED_PRIVATE_KEY


@pytest.mark.usefixtures("saved_encrypted_private_key", "settings_file")
def test_export_encrypted_key(create_handler, password_prompt_mock):
    password_prompt_mock.get_password.return_value = KEY_ENCRYPTION_PASSWORD
    password_prompt_mock.create_password.return_value = b""
    output_file = BytesIO()

    handle = create_handler(ExportContext(key_id=KEY_ID, file=output_file))
    handle()

    password_prompt_mock.get_password.assert_called_once()
    password_prompt_mock.create_password.assert_called_once()
    assert output_file.getvalue() == SERIALIZED_PRIVATE_KEY


@pytest.mark.usefixtures("saved_public_key", "settings_file")
def test_export_public_key(create_handler):
    output_file = BytesIO()

    handle = create_handler(ExportContext(key_id=KEY_ID, file=output_file, public=True))
    handle()

    assert output_file.getvalue() == SERIALIZED_PUBLIC_KEY


@pytest.mark.usefixtures("saved_encrypted_private_key")
def test_export_public_key_from_private_key(
    create_handler, password_prompt_mock, settings_file
):
    remove_public_keys_from_settings(settings_file)

    password_prompt_mock.get_password.return_value = KEY_ENCRYPTION_PASSWORD
    output_file = BytesIO()

    handle = create_handler(ExportContext(key_id=KEY_ID, file=output_file, public=True))
    handle()

    password_prompt_mock.get_password.assert_called_once()
    assert output_file.getvalue() == SERIALIZED_PUBLIC_KEY
