from unittest.mock import MagicMock

import pytest

from gnukek_cli.keys import KeyProvider, PrivateKeyStorage, PublicKeyStorage


@pytest.fixture()
def public_key_storage_mock():
    return MagicMock(PublicKeyStorage)


@pytest.fixture()
def private_key_storage_mock():
    return MagicMock(PrivateKeyStorage)


@pytest.fixture()
def key_provider(public_key_storage_mock, private_key_storage_mock):
    return KeyProvider(public_key_storage_mock, private_key_storage_mock)


def test_get_public_key(key_provider, public_key_storage_mock):
    assert key_provider.get_public_key("key_id")
    public_key_storage_mock.read_public_key.assert_called_once_with("key_id")
    public_key_storage_mock.read_public_key.reset_mock()
    assert key_provider.get_public_key("key_id")
    public_key_storage_mock.read_public_key.assert_not_called()


def test_get_key_pair(key_provider, private_key_storage_mock):
    prompt_password = MagicMock()
    assert key_provider.get_key_pair("key_id", prompt_password)
    private_key_storage_mock.read_private_key.assert_called_once_with(
        "key_id", prompt_password
    )
    private_key_storage_mock.read_private_key.reset_mock()
    assert key_provider.get_key_pair("key_id", prompt_password)
    private_key_storage_mock.read_private_key.assert_not_called()
