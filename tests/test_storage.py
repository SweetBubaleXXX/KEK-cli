import os

from KEK_cli.backend import config_file, KeyStorage
from KEK.hybrid import PrivateKEK

from ._tempdir_setup import TestWithTempdir


class TestKeyStorage(TestWithTempdir):
    def setUp(self):
        super().setUp()
        self.config_path = os.path.join(self.temp_dir.name, "0_config.json")
        self.config = config_file.ConfigFile(self.config_path)
        self.storage = KeyStorage(self.temp_dir.name, self.config)

    def test_key_adding(self):
        generated_key = PrivateKEK.generate()
        self.storage.add(generated_key, "password")
        decoded_key_id = self.storage.decode_key_id(generated_key.key_id)
        self.assertTrue(
            decoded_key_id in self.storage.private_keys
            and decoded_key_id in self.config.private_keys
        )

    def test_key_getting(self):
        generated_key = PrivateKEK.generate()
        self.storage.add(generated_key, "password")
        decoded_key_id = self.storage.decode_key_id(generated_key.key_id)
        key_from_storage = self.storage.get(decoded_key_id, "password")
        self.assertEqual(key_from_storage.key_id, generated_key.key_id)

    def test_key_removing(self):
        generated_key = PrivateKEK.generate()
        self.storage.add(generated_key, "password")
        decoded_key_id = self.storage.decode_key_id(generated_key.key_id)
        self.storage.remove(decoded_key_id)
        self.assertTrue(
            decoded_key_id not in self.storage.private_keys
            and decoded_key_id not in self.config.private_keys
        )
