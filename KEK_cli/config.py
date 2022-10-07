import os

from .backend.config_file import ConfigFile

STORAGE_LOCATION = os.path.expanduser("~/.kek")
CONFIG_LOCATION = os.path.join(STORAGE_LOCATION, "config.json")

config_file = ConfigFile(CONFIG_LOCATION)
