import json
from pathlib import Path

from tests.constants import SAMPLE_SETTINGS


def remove_public_keys_from_settings(settings_path: str | Path):
    with open(settings_path, "w") as f:
        config_with_public_key = SAMPLE_SETTINGS.copy()
        config_with_public_key["public"] = []
        json.dump(config_with_public_key, f)
