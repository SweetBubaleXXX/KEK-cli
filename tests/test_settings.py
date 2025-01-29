import json

import pytest

from gnukek_cli.config import JsonSettingsProvider, Settings
from tests.constants import KEY_ID, PUBLIC_KEY_ID, SAMPLE_SETTINGS


@pytest.fixture()
def settings_file(storage_dir):
    settings_file_path = storage_dir / "config.json"

    with open(settings_file_path, "w") as f:
        json.dump(SAMPLE_SETTINGS, f)

    return settings_file_path


@pytest.fixture()
def json_settings_provider(settings_file):
    return JsonSettingsProvider(settings_file)


def test_json_settings_get(json_settings_provider):
    settings = json_settings_provider.get_settings()

    assert isinstance(settings, Settings)
    assert settings.default == KEY_ID
    assert settings.public == [PUBLIC_KEY_ID]
    assert settings.private == [KEY_ID]


def test_json_settings_save(json_settings_provider, settings_file):
    new_key_id = "abcdef0123456789"

    updated_settings = Settings(**SAMPLE_SETTINGS)
    updated_settings.private.append(new_key_id)
    updated_settings.default = new_key_id

    json_settings_provider.save_settings(updated_settings)

    with open(settings_file) as f:
        settings_content = json.load(f)
        assert settings_content["default"] == new_key_id
        assert settings_content["public"] == [PUBLIC_KEY_ID]
        assert new_key_id in settings_content["private"]
