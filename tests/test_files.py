import os

from KEK.hybrid import PrivateKEK
from KEK_cli.backend import files

from ._tempdir_setup import TestWithTempdir


class TestFiles(TestWithTempdir):
    def test_base_file_rw(self):
        data_for_writing = b"byte data"
        file_path = os.path.join(self.temp_dir.name, "0_file")
        base_file = files.File(file_path)
        base_file.write(data_for_writing)
        self.assertEqual(base_file.read(), data_for_writing)

    def test_key_file_loading(self):
        key_obj = PrivateKEK.generate()
        file_path = os.path.join(self.temp_dir.name, "1_file")
        key_file = files.KeyFile(file_path)
        key_file.export(key_obj)
        new_key_obj = key_file.load()
        self.assertEqual(new_key_obj.key_id, key_obj.key_id)

    def test_file_decryption(self):
        key_obj = PrivateKEK.generate()
        data_for_encryption = b"byte data"
        encrypted_data = key_obj.encrypt(data_for_encryption)
        file_path = os.path.join(self.temp_dir.name, "2_file")
        encrypted_file = files.EncryptedFile(file_path)
        encrypted_file.write(encrypted_data)
        decrypted_data = encrypted_file.decrypt(key_obj)
        self.assertEqual(decrypted_data, data_for_encryption)
