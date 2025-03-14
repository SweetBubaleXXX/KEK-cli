import functools
from io import BytesIO

import pytest
from gnukek.exceptions import VerificationError

from gnukek_cli.command_handlers.verify import VerifyContext, VerifyHandler
from gnukek_cli.utils.exceptions import KeyNotFoundError
from tests.constants import KEY_ENCRYPTION_PASSWORD, KEY_ID, SAMPLE_MESSAGE
from tests.helpers import remove_public_keys_from_settings


@pytest.fixture()
def create_handler(key_provider):
    return functools.partial(VerifyHandler, key_provider=key_provider)


@pytest.mark.usefixtures("saved_public_key", "settings_file")
@pytest.mark.parametrize("chunk_length", [0, 32, 1024])
def test_verify_signature(
    chunk_length, create_handler, message_signature, password_prompt_mock
):
    handle = create_handler(
        VerifyContext(
            signature_file=BytesIO(message_signature),
            original_file=BytesIO(SAMPLE_MESSAGE),
            key_id=KEY_ID,
            chunk_length=chunk_length,
        )
    )
    handle()

    password_prompt_mock.get_password.assert_not_called()


@pytest.mark.usefixtures("saved_encrypted_private_key", "settings_file")
def test_verify_using_private_key(
    create_handler, message_signature, settings_file, password_prompt_mock
):
    password_prompt_mock.get_password.return_value = KEY_ENCRYPTION_PASSWORD
    remove_public_keys_from_settings(settings_file)

    handle = create_handler(
        VerifyContext(
            signature_file=BytesIO(message_signature),
            original_file=BytesIO(SAMPLE_MESSAGE),
            key_id=KEY_ID,
        )
    )
    handle()

    password_prompt_mock.get_password.assert_called_once()


@pytest.mark.usefixtures("saved_public_key", "settings_file")
def test_verify_invalid_signature(create_handler):
    handle = create_handler(
        VerifyContext(
            signature_file=BytesIO(b"invalid_signature"),
            original_file=BytesIO(SAMPLE_MESSAGE),
            key_id=KEY_ID,
        )
    )
    with pytest.raises(VerificationError):
        handle()


def test_verify_no_key_id(create_handler, message_signature):
    handle = create_handler(
        VerifyContext(
            signature_file=BytesIO(message_signature),
            original_file=BytesIO(SAMPLE_MESSAGE),
            key_id=KEY_ID,
        )
    )
    with pytest.raises(KeyNotFoundError):
        handle()
