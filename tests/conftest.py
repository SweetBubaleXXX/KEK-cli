import functools
import io
import json
import os
from base64 import b64decode
from unittest.mock import MagicMock

import pytest
from gnukek.keys import KeyPair, PublicKey

from gnukek_cli.config import JsonSettingsProvider
from gnukek_cli.constants import CONFIG_FILENAME
from gnukek_cli.keys import (
    KeyProvider,
    PrivateKeyFileStorage,
    PublicKeyFileStorage,
    get_private_key_filename,
    get_public_key_filename,
)
from gnukek_cli.passwords import PasswordPrompt
from tests.constants import (
    ENCRYPTED_MESSAGE,
    ENCRYPTED_PRIVATE_KEY,
    KEY_ID,
    MESSAGE_SIGNATURE_ENCODED,
    SAMPLE_SETTINGS,
    SERIALIZED_PRIVATE_KEY,
    SERIALIZED_PUBLIC_KEY,
)


@pytest.fixture()
def sample_public_key():
    return PublicKey.load(SERIALIZED_PUBLIC_KEY)


@pytest.fixture()
def sample_key_pair():
    return KeyPair.load(SERIALIZED_PRIVATE_KEY)


@pytest.fixture
def encrypted_message():
    return b64decode(ENCRYPTED_MESSAGE)


@pytest.fixture
def message_signature():
    return b64decode(MESSAGE_SIGNATURE_ENCODED)


@pytest.fixture()
def storage_dir(tmp_path):
    kek_dir_path = tmp_path / "kek"
    os.mkdir(kek_dir_path)
    return kek_dir_path


@pytest.fixture()
def public_key_file_storage(storage_dir):
    return PublicKeyFileStorage(storage_dir)


@pytest.fixture()
def private_key_file_storage(storage_dir):
    return PrivateKeyFileStorage(storage_dir)


@pytest.fixture()
def settings_provider(storage_dir):
    return JsonSettingsProvider(storage_dir / CONFIG_FILENAME)


@pytest.fixture()
def settings_file(storage_dir):
    settings_file_path = storage_dir / CONFIG_FILENAME

    with open(settings_file_path, "w") as f:
        json.dump(SAMPLE_SETTINGS, f)

    return settings_file_path


@pytest.fixture()
def key_provider(
    public_key_file_storage,
    private_key_file_storage,
    settings_provider,
    password_prompt_mock,
    # settings_file,
):
    return KeyProvider(
        public_key_file_storage,
        private_key_file_storage,
        settings_provider,
        password_prompt_mock,
    )


@pytest.fixture()
def saved_public_key(storage_dir):
    key_path = storage_dir / get_public_key_filename(KEY_ID)
    with open(key_path, "wb") as key_file:
        key_file.write(SERIALIZED_PUBLIC_KEY)


@pytest.fixture()
def saved_private_key(storage_dir):
    key_path = storage_dir / get_private_key_filename(KEY_ID)
    with open(key_path, "wb") as key_file:
        key_file.write(SERIALIZED_PRIVATE_KEY)


@pytest.fixture()
def saved_encrypted_private_key(storage_dir):
    key_path = storage_dir / get_private_key_filename(KEY_ID)
    with open(key_path, "wb") as key_file:
        key_file.write(ENCRYPTED_PRIVATE_KEY)


@pytest.fixture()
def password_prompt_mock():
    mock = MagicMock(PasswordPrompt)
    mock.get_password_callback = functools.partial(
        PasswordPrompt.get_password_callback, mock
    )
    return mock


@pytest.fixture()
def output_buffer():
    return io.BytesIO()
