import os

from ._tempdir_setup import TestWithTempdir

from KEK_cli.backend import files


class TestFiles(TestWithTempdir):
    def test_base_file_rw(self):
        data_for_writing = b"byte data"
        file_path = os.path.join(self.temp_dir.name, "0_file")
        base_file = files.File(file_path)
        base_file.write(data_for_writing)
        self.assertEqual(base_file.read(), data_for_writing)
