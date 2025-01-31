import functools
import json

import pytest

from gnukek_cli.command_handlers.delete_key import DeleteKeyContext, DeleteKeyHandler
from gnukek_cli.keys import get_private_key_filename, get_public_key_filename
from tests.constants import KEY_ID


@pytest.fixture()
def create_handler(
    public_key_file_storage,
    private_key_file_storage,
    settings_provider,
):
    return functools.partial(
        DeleteKeyHandler,
        public_key_storage=public_key_file_storage,
        private_key_storage=private_key_file_storage,
        settings_provider=settings_provider,
    )


@pytest.mark.usefixtures("saved_private_key", "saved_public_key")
@pytest.mark.parametrize("keep_public", [False, True])
def test_delete_key(keep_public, create_handler, storage_dir, settings_file):
    handle = create_handler(DeleteKeyContext(key_ids=[KEY_ID], keep_public=keep_public))
    handle()

    private_key_path = storage_dir / get_private_key_filename(KEY_ID)
    assert not private_key_path.exists()
    public_key_path = storage_dir / get_public_key_filename(KEY_ID)
    assert public_key_path.exists() == keep_public

    with open(settings_file, "rb") as f:
        settings_content = json.load(f)
        assert KEY_ID not in settings_content["private"]
        assert (KEY_ID in settings_content["public"]) == keep_public
        assert settings_content["default"] is None
