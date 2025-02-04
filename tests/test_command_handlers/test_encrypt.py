import functools
from io import BytesIO
from typing import BinaryIO
from unittest.mock import MagicMock

import pytest

from gnukek_cli.command_handlers.encrypt import EncryptContext, EncryptHandler
from gnukek_cli.exceptions import KeyNotFoundError
from tests.constants import KEY_ENCRYPTION_PASSWORD, KEY_ID, SAMPLE_MESSAGE
from tests.helpers import remove_public_keys_from_settings


@pytest.fixture()
def create_handler(
    public_key_file_storage,
    private_key_file_storage,
    settings_provider,
    password_prompt_mock,
):
    return functools.partial(
        EncryptHandler,
        public_key_storage=public_key_file_storage,
        private_key_storage=private_key_file_storage,
        settings_provider=settings_provider,
        password_prompt=password_prompt_mock,
    )


@pytest.mark.usefixtures("saved_public_key", "settings_file")
def test_encrypt_using_default_public_key(create_handler, sample_key_pair):
    output_buffer = BytesIO()
    handle = create_handler(
        EncryptContext(input_file=BytesIO(SAMPLE_MESSAGE), output_file=output_buffer)
    )
    handle()

    encrypted_message = output_buffer.getvalue()
    assert len(encrypted_message) > len(SAMPLE_MESSAGE)

    decrypted_message = sample_key_pair.decrypt(encrypted_message)
    assert decrypted_message == SAMPLE_MESSAGE


@pytest.mark.usefixtures("saved_public_key", "settings_file")
def test_encrypt_no_chunk(create_handler):
    output_buffer_mock = MagicMock(BinaryIO)
    handle = create_handler(
        EncryptContext(
            input_file=BytesIO(SAMPLE_MESSAGE),
            output_file=output_buffer_mock,
            chunk_length=0,
        )
    )
    handle()

    assert output_buffer_mock.write.call_count == 2


@pytest.mark.usefixtures("saved_encrypted_private_key", "settings_file")
def test_encrypt_using_private_key(
    create_handler,
    sample_key_pair,
    password_prompt_mock,
    settings_file,
):
    remove_public_keys_from_settings(settings_file)

    password_prompt_mock.get_password.return_value = KEY_ENCRYPTION_PASSWORD
    output_buffer = BytesIO()

    handle = create_handler(
        EncryptContext(
            input_file=BytesIO(SAMPLE_MESSAGE), output_file=output_buffer, key_id=KEY_ID
        )
    )
    handle()

    password_prompt_mock.get_password.assert_called_once()

    encrypted_message = output_buffer.getvalue()
    decrypted_message = sample_key_pair.decrypt(encrypted_message)
    assert decrypted_message == SAMPLE_MESSAGE


def test_encrypt_no_key_id(create_handler):
    handle = create_handler(
        EncryptContext(input_file=BytesIO(SAMPLE_MESSAGE), output_file=BytesIO())
    )
    with pytest.raises(KeyNotFoundError):
        handle()
