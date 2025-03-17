import logging
import random

from gnukek.keys import KeyPair, PublicKey

from gnukek_cli.config import SettingsProvider
from gnukek_cli.keys.storages import PrivateKeyStorage, PublicKeyStorage
from gnukek_cli.utils.exceptions import KeyNotFoundError
from gnukek_cli.utils.passwords import PasswordPrompt

logger = logging.getLogger(__name__)


class KeyProvider:
    def __init__(
        self,
        public_key_storage: PublicKeyStorage,
        private_key_storage: PrivateKeyStorage,
        settings_provider: SettingsProvider,
        password_prompt: PasswordPrompt,
    ) -> None:
        self.settings_provider = settings_provider
        self._public_key_storage = public_key_storage
        self._private_key_storage = private_key_storage
        self._password_prompt = password_prompt
        self._public_key_cache: dict[str, PublicKey] = {}
        self._key_pair_cache: dict[str, KeyPair] = {}

    def get_public_key(self, key_id: str | None = None) -> PublicKey:
        key_id = self._get_key_id(key_id)
        if key_id in self._public_key_cache:
            logger.debug(f"Public key for {key_id} retrieved from cache")
            return self._public_key_cache[key_id]
        if key_id in self._key_pair_cache:
            logger.debug(f"Public key for {key_id} retrieved from key pair cache")
            return self._key_pair_cache[key_id].public_key

        public_key = self._read_public_key(key_id)
        self._public_key_cache[key_id] = public_key
        logger.debug(f"Public key for {key_id} read from storage")
        return public_key

    def get_key_pair(self, key_id: str | None = None) -> KeyPair:
        key_id = self._get_key_id(key_id)
        if key_id in self._key_pair_cache:
            logger.debug(f"Key pair for {key_id} retrieved from cache")
            return self._key_pair_cache[key_id]

        key_pair = self._read_key_pair(key_id)
        self._key_pair_cache[key_id] = key_pair
        logger.debug(f"Key pair for {key_id} read from storage")
        return key_pair

    def add_public_key(self, public_key: PublicKey) -> None:
        settings = self.settings_provider.get_settings()
        key_id = public_key.key_id.hex()

        self._public_key_cache[key_id] = public_key
        self._public_key_storage.save_public_key(public_key)
        if key_id not in settings.public:
            settings.public.append(key_id)
            self.settings_provider.save_settings(settings)
        logger.debug(f"Public key for {key_id} added")

    def add_key_pair(self, key_pair: KeyPair, password: bytes | None = None) -> None:
        settings = self.settings_provider.get_settings()
        key_id = key_pair.key_id.hex()

        self._key_pair_cache[key_id] = key_pair
        self._public_key_cache[key_id] = key_pair.public_key
        self._private_key_storage.save_private_key(key_pair, password)
        self._public_key_storage.save_public_key(key_pair.public_key)

        if key_id not in settings.private:
            settings.private.append(key_id)
        if key_id not in settings.public:
            settings.public.append(key_id)
        if not settings.default:
            settings.default = key_id

        self.settings_provider.save_settings(settings)
        logger.debug(f"Key pair for {key_id} added")

    def remove_public_key(self, key_id: str) -> None:
        settings = self.settings_provider.get_settings()

        if key_id not in settings.public:
            raise KeyNotFoundError(key_id)

        self._public_key_storage.delete_public_key(key_id)
        settings.public.remove(key_id)

        self.settings_provider.save_settings(settings)
        logger.debug(f"Public key for {key_id} removed")

    def remove_private_key(self, key_id: str) -> None:
        settings = self.settings_provider.get_settings()

        if key_id not in settings.private:
            raise KeyNotFoundError(key_id)

        self._private_key_storage.delete_private_key(key_id)
        settings.private.remove(key_id)
        if settings.default == key_id:
            settings.default = (
                random.choice(settings.private) if settings.private else None
            )

        self.settings_provider.save_settings(settings)
        logger.debug(f"Private key for {key_id} removed")

    def _get_key_id(self, key_id: str | None) -> str:
        settings = self.settings_provider.get_settings()
        if not key_id:
            key_id = settings.default
        if not key_id:
            raise KeyNotFoundError("default")
        return key_id

    def _read_public_key(self, key_id: str) -> PublicKey:
        settings = self.settings_provider.get_settings()
        if key_id in settings.public:
            return self._public_key_storage.read_public_key(key_id)
        if key_id in settings.private:
            key_pair = self._private_key_storage.read_private_key(
                key_id, self._password_prompt.get_password_callback(key_id)
            )
            return key_pair.public_key
        raise KeyNotFoundError(key_id)

    def _read_key_pair(self, key_id: str) -> KeyPair:
        settings = self.settings_provider.get_settings()
        if key_id not in settings.private:
            raise KeyNotFoundError(key_id)
        return self._private_key_storage.read_private_key(
            key_id, self._password_prompt.get_password_callback(key_id)
        )
