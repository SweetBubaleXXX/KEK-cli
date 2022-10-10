import os

from KEK_cli.backend import config_file

from ._tempdir_setup import TestWithTempdir


class TestKeyStorage(TestWithTempdir):
    def setUp(self):
        super().setUp()
        self.config_path = os.path.join(self.temp_dir.name, "0_config.json")
        self.config = config_file.ConfigFile(self.config_path)
