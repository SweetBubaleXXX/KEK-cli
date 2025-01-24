import os

import pytest
from gnukek import PublicKey

from gnukek_cli.exceptions import KeyNotFoundError
from gnukek_cli.keys import get_public_key_filename
from tests.constants import KEY_ID, SERIALIZED_PUBLIC_KEY


@pytest.fixture()
def saved_public_key(storage_dir):
    key_path = storage_dir / get_public_key_filename(KEY_ID.hex())
    with open(key_path, "wb") as key_file:
        key_file.write(SERIALIZED_PUBLIC_KEY)


@pytest.mark.usefixtures("saved_public_key")
def test_read_public_key(public_key_file_storage):
    found_public_key = public_key_file_storage.read_public_key(KEY_ID.hex())
    assert isinstance(found_public_key, PublicKey)
    assert found_public_key.key_id == KEY_ID


def test_read_public_key_not_exists(public_key_file_storage):
    with pytest.raises(KeyNotFoundError):
        public_key_file_storage.read_public_key("unknown_key")


def test_save_public_key(public_key_file_storage, sample_public_key, storage_dir):
    public_key_file_storage.save_public_key(sample_public_key)

    key_path = storage_dir / get_public_key_filename(KEY_ID.hex())
    assert os.path.exists(key_path)
    with open(key_path, "rb") as key_file:
        serialized_key = key_file.read()
        assert serialized_key == SERIALIZED_PUBLIC_KEY


@pytest.mark.usefixtures("saved_public_key")
def test_delete_public_key(public_key_file_storage, storage_dir):
    public_key_file_storage.delete_public_key(KEY_ID.hex())

    key_path = storage_dir / get_public_key_filename(KEY_ID.hex())
    assert not os.path.exists(key_path)


def test_delete_public_key_not_exists(public_key_file_storage):
    with pytest.raises(KeyNotFoundError):
        public_key_file_storage.delete_public_key("unknown_key")
