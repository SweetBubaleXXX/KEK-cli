import os

import click
from dependency_injector import containers, providers

from gnukek_cli.config import JsonSettingsProvider
from gnukek_cli.constants import CONFIG_FILENAME
from gnukek_cli.keys.provider import KeyProvider
from gnukek_cli.keys.storages import PrivateKeyFileStorage, PublicKeyFileStorage
from gnukek_cli.utils.passwords import ClickPasswordPrompt


class Container(containers.DeclarativeContainer):
    config = providers.Configuration()
    wiring_config = containers.WiringConfiguration(
        packages=[
            "gnukek_cli.command_handlers",
        ],
        modules=[
            "gnukek_cli.utils.completions",
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

    password_prompt = providers.Singleton(ClickPasswordPrompt)

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
        settings_provider=settings_provider,
        password_prompt=password_prompt,
    )

    output_buffer = providers.Singleton(click.get_binary_stream, "stdout")
