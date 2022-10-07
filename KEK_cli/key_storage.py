from .backend import KeyStorage
from .config import STORAGE_LOCATION, config_file

key_storage = KeyStorage(STORAGE_LOCATION, config_file)
