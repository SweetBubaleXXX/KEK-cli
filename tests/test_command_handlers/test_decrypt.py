import functools
from io import BytesIO

import pytest

from gnukek_cli.command_handlers.decrypt import DecryptContext, DecryptHandler
from gnukek_cli.exceptions import KeyNotFoundError
from tests.constants import KEY_ENCRYPTION_PASSWORD, SAMPLE_MESSAGE


@pytest.fixture()
def create_handler(
    private_key_file_storage,
    settings_provider,
    password_prompt_mock,
):
    return functools.partial(
        DecryptHandler,
        private_key_storage=private_key_file_storage,
        settings_provider=settings_provider,
        password_prompt=password_prompt_mock,
    )


@pytest.mark.usefixtures("saved_encrypted_private_key", "settings_file")
@pytest.mark.parametrize("chunk_length", [0, 32, 1024])
def test_decrypt(chunk_length, create_handler, password_prompt_mock, encrypted_message):
    password_prompt_mock.get_password.return_value = KEY_ENCRYPTION_PASSWORD

    output_buffer = BytesIO()
    handle = create_handler(
        DecryptContext(
            input_file=BytesIO(encrypted_message),  # type: ignore
            output_file=output_buffer,
            chunk_length=chunk_length,
        )
    )
    handle()

    decrypted_message = output_buffer.getvalue()
    assert decrypted_message == SAMPLE_MESSAGE

    password_prompt_mock.get_password.assert_called_once()


def test_decrypt_no_key_found(create_handler, encrypted_message):
    handle = create_handler(
        DecryptContext(
            input_file=BytesIO(encrypted_message),  # type: ignore
            output_file=BytesIO(),
        )
    )
    with pytest.raises(KeyNotFoundError):
        handle()
