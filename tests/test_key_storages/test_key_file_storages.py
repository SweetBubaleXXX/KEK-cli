import os

import pytest
from gnukek import KeyPair, PublicKey
from gnukek.constants import SerializedKeyType
from gnukek.utils import get_key_type

from gnukek_cli.exceptions import KeyNotFoundError
from gnukek_cli.keys import get_private_key_filename, get_public_key_filename
from tests.constants import (
    ENCRYPTED_PRIVATE_KEY,
    KEY_ENCRYPTION_PASSWORD,
    KEY_ID,
    KEY_ID_BYTES,
    SERIALIZED_PRIVATE_KEY,
    SERIALIZED_PUBLIC_KEY,
)


@pytest.mark.usefixtures("saved_public_key")
def test_read_public_key(public_key_file_storage):
    found_public_key = public_key_file_storage.read_public_key(KEY_ID)
    assert isinstance(found_public_key, PublicKey)
    assert found_public_key.key_id == KEY_ID_BYTES


def test_read_public_key_not_exists(public_key_file_storage):
    with pytest.raises(KeyNotFoundError):
        public_key_file_storage.read_public_key("unknown_key")


def test_save_public_key(public_key_file_storage, sample_public_key, storage_dir):
    public_key_file_storage.save_public_key(sample_public_key)

    key_path = storage_dir / get_public_key_filename(KEY_ID)
    assert os.path.exists(key_path)
    with open(key_path, "rb") as key_file:
        serialized_key = key_file.read()
        assert serialized_key == SERIALIZED_PUBLIC_KEY


@pytest.mark.usefixtures("saved_public_key")
def test_delete_public_key(public_key_file_storage, storage_dir):
    public_key_file_storage.delete_public_key(KEY_ID)

    key_path = storage_dir / get_public_key_filename(KEY_ID)
    assert not os.path.exists(key_path)


def test_delete_public_key_not_exists(public_key_file_storage):
    with pytest.raises(KeyNotFoundError):
        public_key_file_storage.delete_public_key("unknown_key")


@pytest.mark.usefixtures("saved_public_key")
def test_public_key_contains(public_key_file_storage):
    assert KEY_ID in public_key_file_storage
    assert KEY_ID_BYTES in public_key_file_storage
    assert "unknown_key" not in public_key_file_storage


@pytest.mark.usefixtures("saved_encrypted_private_key")
def test_read_private_key_raw(private_key_file_storage):
    serialized_key = private_key_file_storage.read_private_key_raw(KEY_ID)
    assert serialized_key == ENCRYPTED_PRIVATE_KEY


@pytest.mark.usefixtures("saved_private_key")
def test_read_private_key(private_key_file_storage):
    found_key_pair = private_key_file_storage.read_private_key(
        KEY_ID, prompt_password=bytes
    )
    assert isinstance(found_key_pair, KeyPair)
    assert found_key_pair.key_id == KEY_ID_BYTES


@pytest.mark.usefixtures("saved_encrypted_private_key")
def test_read_encrypted_private_key(private_key_file_storage):
    found_key_pair = private_key_file_storage.read_private_key(
        KEY_ID, prompt_password=lambda: KEY_ENCRYPTION_PASSWORD
    )
    assert isinstance(found_key_pair, KeyPair)
    assert found_key_pair.key_id == KEY_ID_BYTES


def test_read_private_key_not_exists(private_key_file_storage):
    with pytest.raises(KeyNotFoundError):
        private_key_file_storage.read_private_key("unknown_key", prompt_password=bytes)


def test_save_private_key(private_key_file_storage, sample_key_pair, storage_dir):
    private_key_file_storage.save_private_key(sample_key_pair)

    key_path = storage_dir / get_private_key_filename(KEY_ID)
    assert os.path.exists(key_path)
    with open(key_path, "rb") as key_file:
        serialized_key = key_file.read()
        assert serialized_key == SERIALIZED_PRIVATE_KEY


def test_save_encrypted_private_key(
    private_key_file_storage, sample_key_pair, storage_dir
):
    private_key_file_storage.save_private_key(
        sample_key_pair, password=KEY_ENCRYPTION_PASSWORD
    )

    key_path = storage_dir / get_private_key_filename(KEY_ID)
    assert os.path.exists(key_path)
    with open(key_path, "rb") as key_file:
        serialized_key = key_file.read()
        assert get_key_type(serialized_key) == SerializedKeyType.ENCRYPTED_PRIVATE_KEY


@pytest.mark.usefixtures("saved_private_key")
def test_delete_private_key(private_key_file_storage, storage_dir):
    private_key_file_storage.delete_private_key(KEY_ID)

    key_path = storage_dir / get_private_key_filename(KEY_ID)
    assert not os.path.exists(key_path)


def test_delete_private_key_not_exists(private_key_file_storage):
    with pytest.raises(KeyNotFoundError):
        private_key_file_storage.delete_private_key("unknown_key")


@pytest.mark.usefixtures("saved_private_key")
def test_private_key_contains(private_key_file_storage):
    assert KEY_ID in private_key_file_storage
    assert KEY_ID_BYTES in private_key_file_storage
    assert "unknown_key" not in private_key_file_storage
