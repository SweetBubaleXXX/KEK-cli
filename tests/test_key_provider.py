from unittest.mock import MagicMock

import pytest

from gnukek_cli.exceptions import KeyNotFoundError
from gnukek_cli.keys import KeyProvider, PrivateKeyStorage, PublicKeyStorage
from tests.constants import KEY_ID
from tests.helpers import remove_public_keys_from_settings


@pytest.fixture()
def public_key_storage_mock():
    return MagicMock(PublicKeyStorage)


@pytest.fixture()
def private_key_storage_mock():
    return MagicMock(PrivateKeyStorage)


@pytest.fixture()
def key_provider(
    public_key_storage_mock,
    private_key_storage_mock,
    settings_provider,
    password_prompt_mock,
):
    return KeyProvider(
        public_key_storage_mock,
        private_key_storage_mock,
        settings_provider,
        password_prompt_mock,
    )


@pytest.mark.usefixtures("settings_file")
def test_get_public_key(key_provider, public_key_storage_mock):
    assert key_provider.get_public_key(KEY_ID)
    public_key_storage_mock.read_public_key.assert_called_once_with(KEY_ID)

    public_key_storage_mock.read_public_key.reset_mock()

    assert key_provider.get_public_key(KEY_ID)
    public_key_storage_mock.read_public_key.assert_not_called()


@pytest.mark.usefixtures("settings_file")
def test_get_public_key_from_private(
    key_provider, private_key_storage_mock, settings_file
):
    remove_public_keys_from_settings(settings_file)
    key_provider.settings_provider.load()

    assert key_provider.get_public_key(KEY_ID)
    private_key_storage_mock.read_private_key.assert_called_once()


def test_get_public_key_empty_settings(key_provider):
    with pytest.raises(KeyNotFoundError):
        key_provider.get_public_key(KEY_ID)


@pytest.mark.usefixtures("settings_file")
def test_get_key_pair(key_provider, private_key_storage_mock):
    assert key_provider.get_key_pair(KEY_ID)
    private_key_storage_mock.read_private_key.assert_called_once()

    private_key_storage_mock.read_private_key.reset_mock()

    assert key_provider.get_key_pair(KEY_ID)
    private_key_storage_mock.read_private_key.assert_not_called()


@pytest.mark.usefixtures("settings_file")
def test_get_default_key_pair(key_provider, private_key_storage_mock):
    assert key_provider.get_key_pair()
    private_key_storage_mock.read_private_key.assert_called_once()


def test_get_key_pair_empty_settings(key_provider):
    with pytest.raises(KeyNotFoundError):
        key_provider.get_key_pair(KEY_ID)
