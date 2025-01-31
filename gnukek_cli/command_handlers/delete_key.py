import random
from collections.abc import Iterable
from dataclasses import dataclass

from dependency_injector.wiring import Provide, inject

from gnukek_cli.config import SettingsProvider
from gnukek_cli.container import Container
from gnukek_cli.keys import PrivateKeyStorage, PublicKeyStorage


@dataclass
class DeleteKeyContext:
    key_ids: Iterable[str]
    keep_public: bool = False


class DeleteKeyHandler:
    @inject
    def __init__(
        self,
        context: DeleteKeyContext,
        *,
        public_key_storage: PublicKeyStorage = Provide[Container.public_key_storage],
        private_key_storage: PrivateKeyStorage = Provide[Container.private_key_storage],
        settings_provider: SettingsProvider = Provide[Container.settings_provider],
    ) -> None:
        self.context = context
        self._public_key_storage = public_key_storage
        self._private_key_storage = private_key_storage
        self._settings_provider = settings_provider

    def __call__(self) -> None:
        self._settings = self._settings_provider.get_settings()

        for key in self.context.key_ids:
            self._delete_key_pair(key)

        self._settings_provider.save_settings(self._settings)

    def _delete_key_pair(self, key_id: str) -> None:
        if key_id in self._settings.private:
            self._private_key_storage.delete_private_key(key_id)
            self._settings.private.remove(key_id)
            if self._settings.default == key_id:
                self._settings.default = (
                    random.choice(self._settings.private)
                    if self._settings.private
                    else None
                )

        if not self.context.keep_public:
            if key_id in self._settings.public:
                self._public_key_storage.delete_public_key(key_id)
                self._settings.public.remove(key_id)
