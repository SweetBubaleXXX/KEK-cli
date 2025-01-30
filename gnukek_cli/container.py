import os
import sys

from dependency_injector import containers, providers

from gnukek_cli.config import JsonSettingsProvider
from gnukek_cli.constants import CONFIG_FILENAME
from gnukek_cli.keys import KeyProvider, PrivateKeyFileStorage, PublicKeyFileStorage
from gnukek_cli.passwords import ClickPasswordPrompt


class Container(containers.DeclarativeContainer):
    config = providers.Configuration()
    wiring_config = containers.WiringConfiguration(
        packages=[
            "gnukek_cli.command_handlers",
            "gnukek_cli.commands",
        ],
    )

    settings_provider = providers.Singleton(
        JsonSettingsProvider,
        settings_path=providers.Callable(
            os.path.join,
            config.key_storage_path,
            CONFIG_FILENAME,
        ),
    )

    public_key_storage = providers.Factory(
        PublicKeyFileStorage, base_path=config.key_storage_path
    )
    private_key_storage = providers.Factory(
        PrivateKeyFileStorage, base_path=config.key_storage_path
    )
    key_provider = providers.Singleton(
        KeyProvider,
        public_key_storage=public_key_storage,
        private_key_storage=private_key_storage,
    )

    password_prompt = providers.Singleton(ClickPasswordPrompt)
    output_buffer = providers.Object(sys.stdout.buffer)
