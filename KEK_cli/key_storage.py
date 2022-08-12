import os

from .backend import KeyStorage

STORAGE_LOCATION = os.path.expanduser("~/.kek")

key_storage = KeyStorage(STORAGE_LOCATION)
