from dependency_injector import containers, providers

from gnukek_cli.keys import KeyProvider, PrivateKeyFileStorage, PublicKeyFileStorage


class Container(containers.DeclarativeContainer):
    config = providers.Configuration()

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
