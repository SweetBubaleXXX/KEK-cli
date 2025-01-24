import os

import pytest
from gnukek import PublicKey

from gnukek_cli.keys import PublicKeyFileStorage
from tests.constants import SERIALIZED_PUBLIC_KEY


@pytest.fixture()
def sample_public_key():
    return PublicKey.load(SERIALIZED_PUBLIC_KEY)


@pytest.fixture()
def storage_dir(tmp_path):
    kek_dir_path = tmp_path / "kek"
    os.mkdir(kek_dir_path)
    return kek_dir_path


@pytest.fixture()
def public_key_file_storage(storage_dir):
    return PublicKeyFileStorage(storage_dir)
