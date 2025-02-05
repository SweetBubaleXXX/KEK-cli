import functools
from io import BytesIO

import pytest

from gnukek_cli.command_handlers.sign import SignContext, SignHandler
from gnukek_cli.exceptions import KeyNotFoundError
from tests.constants import KEY_ID, SAMPLE_MESSAGE


@pytest.fixture()
def create_handler(
    private_key_file_storage,
    settings_provider,
    password_prompt_mock,
):
    return functools.partial(
        SignHandler,
        private_key_storage=private_key_file_storage,
        settings_provider=settings_provider,
        password_prompt=password_prompt_mock,
    )


@pytest.mark.usefixtures("saved_private_key", "settings_file")
@pytest.mark.parametrize("key_id", [None, KEY_ID])
def test_sign(key_id, create_handler, sample_public_key):
    output_buffer = BytesIO()
    handle = create_handler(
        SignContext(
            input_file=BytesIO(SAMPLE_MESSAGE), output_file=output_buffer, key_id=key_id
        )
    )
    handle()

    signature = output_buffer.getvalue()
    assert sample_public_key.verify(signature, message=SAMPLE_MESSAGE)


def test_sign_no_key_found(create_handler):
    handle = create_handler(
        SignContext(input_file=BytesIO(SAMPLE_MESSAGE), output_file=BytesIO())
    )
    with pytest.raises(KeyNotFoundError):
        handle()
