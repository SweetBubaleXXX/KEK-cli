import io
import json
import os
from unittest.mock import MagicMock

import pytest
from gnukek import KeyPair, PublicKey

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
    ENCRYPTED_PRIVATE_KEY,
    KEY_ID,
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
def key_provider(public_key_file_storage, private_key_file_storage):
    return KeyProvider(public_key_file_storage, private_key_file_storage)


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
    return MagicMock(PasswordPrompt)


@pytest.fixture()
def output_buffer():
    return io.BytesIO()
