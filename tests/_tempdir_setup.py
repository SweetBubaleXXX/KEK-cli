import unittest
from tempfile import TemporaryDirectory


class TestWithTempdir(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory(prefix="test_", suffix="_kek-cli")

    def tearDown(self):
        self.temp_dir.cleanup()
