import os

from KEK_cli.backend import ConfigFile

from ._tempdir_setup import TestWithTempdir


class TestConfig(TestWithTempdir):
    def test_config_file_creation(self):
        config_path = os.path.join(self.temp_dir.name, "0_config.json")
        config = ConfigFile(config_path)
        config.write()
        self.assertTrue(os.path.isfile(config_path))

    def test_config_file_reading(self):
        test_key_id = "key id"
        config_path = os.path.join(self.temp_dir.name, "1_config.json")
        config = ConfigFile(config_path)
        config.private_keys.add(test_key_id)
        config.write()
        config_for_reading = ConfigFile(config_path)
        self.assertIn(test_key_id, config_for_reading.private_keys)
