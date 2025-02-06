from unittest.mock import MagicMock

import pytest

from gnukek_cli.exceptions import KeyNotFoundError
from gnukek_cli.keys.provider import KeyProvider, PrivateKeyStorage, PublicKeyStorage
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


def test_add_public_key(
    key_provider, sample_public_key, public_key_storage_mock, settings_provider
):
    key_provider.add_public_key(sample_public_key)

    public_key_storage_mock.save_public_key.assert_called_once()

    settings = settings_provider.load()
    assert KEY_ID in settings.public


def test_add_key_pair(
    key_provider,
    sample_key_pair,
    public_key_storage_mock,
    private_key_storage_mock,
    settings_provider,
):
    key_provider.add_key_pair(sample_key_pair)

    public_key_storage_mock.save_public_key.assert_called_once()
    private_key_storage_mock.save_private_key.assert_called_once_with(
        sample_key_pair, None
    )

    settings = settings_provider.load()
    assert KEY_ID in settings.private
    assert KEY_ID in settings.public
    assert settings.default == KEY_ID


@pytest.mark.usefixtures("settings_file")
def test_remove_public_key(key_provider, public_key_storage_mock, settings_provider):
    key_provider.remove_public_key(KEY_ID)

    public_key_storage_mock.delete_public_key.assert_called_once_with(KEY_ID)

    settings = settings_provider.load()
    assert KEY_ID not in settings.public


@pytest.mark.usefixtures("settings_file")
def test_remove_private_key(key_provider, private_key_storage_mock, settings_provider):
    key_provider.remove_private_key(KEY_ID)

    private_key_storage_mock.delete_private_key.assert_called_once_with(KEY_ID)

    settings = settings_provider.load()
    assert KEY_ID not in settings.private
    assert settings.default is None
