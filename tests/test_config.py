import json

import pytest

from gnukek_cli.config import Config, JsonConfigProvider
from tests.constants import KEY_ID, PUBLIC_KEY_ID, SAMPLE_CONFIG


@pytest.fixture()
def config_file(storage_dir):
    config_file_path = storage_dir / "config.json"

    with open(config_file_path, "w") as f:
        json.dump(SAMPLE_CONFIG, f)

    return config_file_path


@pytest.fixture()
def json_config_provider(config_file):
    return JsonConfigProvider(config_file)


def test_json_config_get(json_config_provider):
    config = json_config_provider.get_config()

    assert isinstance(config, Config)
    assert config.default == KEY_ID
    assert config.public == [PUBLIC_KEY_ID]
    assert config.private == [KEY_ID]


def test_json_config_save(json_config_provider, config_file):
    new_key_id = "abcdef0123456789"

    updated_config = Config(**SAMPLE_CONFIG)
    updated_config.private.append(new_key_id)
    updated_config.default = new_key_id

    json_config_provider.save_config(updated_config)

    with open(config_file) as f:
        config_content = json.load(f)
        assert config_content["default"] == new_key_id
        assert config_content["public"] == [PUBLIC_KEY_ID]
        assert new_key_id in config_content["private"]
