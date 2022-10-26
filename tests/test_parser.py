import os

from KEK_cli import config, key_storage
from KEK_cli.adapter import KeyStorage
from KEK_cli.backend import ConfigFile, KeyStorage

from ._tempdir_setup import TestWithTempdir


class TestParser(TestWithTempdir):
    def setUp(self):
        super().setUp()
        config_path = os.path.join(
            self.temp_dir.name, "0_config.json"
        )
        config.config_file = ConfigFile(config_path)
        key_storage.key_storage = KeyStorage(
            self.temp_dir.name, config.config_file
        )
        from KEK_cli import parser
        self.parser = parser.parser

    def __execute_command(self, arg_list: list):
        args = self.parser.parse_args(arg_list)
        args.func(args)

    def test_info(self):
        self.__execute_command(["info"])

    def test_list(self):
        self.__execute_command(["list"])

    def test_decryption(self):
        data_for_encryption = b"byte data"
        file_path = os.path.join(self.temp_dir.name, "file")
        encrypted_file_path = os.path.join(
            self.temp_dir.name, "encrypted_file"
        )
        decrypted_file_path = os.path.join(
            self.temp_dir.name, "decrypted_file"
        )
        with open(file_path, "wb") as file:
            file.write(data_for_encryption)
        self.__execute_command(["generate", "--nopass"])
        self.__execute_command(
            ["encrypt", "--output", encrypted_file_path, file_path]
        )
        self.__execute_command(
            ["decrypt", "--output", decrypted_file_path, encrypted_file_path]
        )
        with open(decrypted_file_path, "rb") as file:
            self.assertEqual(file.read(), data_for_encryption)
