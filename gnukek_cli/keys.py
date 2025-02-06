from abc import ABCMeta, abstractmethod
from pathlib import Path

from gnukek.constants import SerializedKeyType
from gnukek.keys import KeyPair, PublicKey
from gnukek.utils import get_key_type

from gnukek_cli.config import SettingsProvider
from gnukek_cli.exceptions import KeyNotFoundError
from gnukek_cli.passwords import PasswordPrompt, PromptPasswordCallback


class PublicKeyStorage(metaclass=ABCMeta):
    @abstractmethod
    def read_public_key(self, key_id: str) -> PublicKey: ...

    @abstractmethod
    def save_public_key(self, public_key: PublicKey) -> None: ...

    @abstractmethod
    def delete_public_key(self, key_id: str) -> None: ...

    @abstractmethod
    def __contains__(self, obj: object) -> bool: ...


class PrivateKeyStorage(metaclass=ABCMeta):
    @abstractmethod
    def read_private_key_raw(self, key_id: str) -> bytes: ...

    @abstractmethod
    def read_private_key(
        self, key_id: str, prompt_password: PromptPasswordCallback
    ) -> KeyPair: ...

    @abstractmethod
    def save_private_key(
        self, key_pair: KeyPair, password: bytes | None = None
    ) -> None: ...

    @abstractmethod
    def delete_private_key(self, key_id: str) -> None: ...

    @abstractmethod
    def __contains__(self, obj: object) -> bool: ...


def get_public_key_filename(key_id: str) -> str:
    return f"{key_id}.pub.kek"


def get_private_key_filename(key_id: str) -> str:
    return f"{key_id}.kek"


class PublicKeyFileStorage(PublicKeyStorage):
    def __init__(self, base_path: str) -> None:
        self._base_path = Path(base_path)

    def read_public_key(self, key_id: str) -> PublicKey:
        key_path = self._get_key_path(key_id)

        if not key_path.is_file():
            raise KeyNotFoundError(key_id)

        with open(key_path, "rb") as key_file:
            serialized_key = key_file.read()

        return PublicKey.load(serialized_key)

    def save_public_key(self, public_key: PublicKey) -> None:
        key_path = self._get_key_path(public_key.key_id.hex())

        serialized_key = public_key.serialize()

        with open(key_path, "wb") as key_file:
            key_file.write(serialized_key)

    def delete_public_key(self, key_id: str) -> None:
        key_path = self._get_key_path(key_id)

        if not key_path.is_file():
            raise KeyNotFoundError(key_id)

        key_path.unlink()

    def __contains__(self, obj: object) -> bool:
        if isinstance(obj, str):
            key_id = obj
        elif isinstance(obj, bytes):
            key_id = obj.hex()
        else:
            raise TypeError(f"Unsupported type: {type(obj)}")

        key_path = self._get_key_path(key_id)
        return key_path.is_file()

    def _get_key_path(self, key_id: str) -> Path:
        key_filename = get_public_key_filename(key_id)
        return self._base_path / key_filename


class PrivateKeyFileStorage(PrivateKeyStorage):
    def __init__(self, base_path: str) -> None:
        self._base_path = Path(base_path)

    def read_private_key_raw(self, key_id: str) -> bytes:
        key_path = self._get_key_path(key_id)

        if not key_path.is_file():
            raise KeyNotFoundError(key_id)

        with open(key_path, "rb") as key_file:
            return key_file.read()

    def read_private_key(
        self, key_id: str, prompt_password: PromptPasswordCallback
    ) -> KeyPair:
        serialized_key = self.read_private_key_raw(key_id)
        key_type = get_key_type(serialized_key)

        if key_type == SerializedKeyType.ENCRYPTED_PRIVATE_KEY:
            password = prompt_password()
        else:
            password = None

        return KeyPair.load(serialized_key, password=password)

    def save_private_key(
        self, key_pair: KeyPair, password: bytes | None = None
    ) -> None:
        key_path = self._get_key_path(key_pair.key_id.hex())

        serialized_key = key_pair.serialize(password=password)

        with open(key_path, "wb") as key_file:
            key_file.write(serialized_key)

    def delete_private_key(self, key_id: str) -> None:
        key_path = self._get_key_path(key_id)

        if not key_path.is_file():
            raise KeyNotFoundError(key_id)

        key_path.unlink()

    def __contains__(self, obj: object) -> bool:
        if isinstance(obj, str):
            key_id = obj
        elif isinstance(obj, bytes):
            key_id = obj.hex()
        else:
            raise TypeError(f"Unsupported type: {type(obj)}")

        key_path = self._get_key_path(key_id)
        return key_path.is_file()

    def _get_key_path(self, key_id: str) -> Path:
        key_filename = get_private_key_filename(key_id)
        return self._base_path / key_filename


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
            return self._public_key_cache[key_id]

        public_key = self._read_public_key(key_id)
        self._public_key_cache[key_id] = public_key
        return public_key

    def get_key_pair(self, key_id: str | None = None) -> KeyPair:
        key_id = self._get_key_id(key_id)
        if key_id in self._key_pair_cache:
            return self._key_pair_cache[key_id]

        key_pair = self._read_key_pair(key_id)
        self._key_pair_cache[key_id] = key_pair
        return key_pair

    def add_public_key(self, public_key: PublicKey) -> None:
        settings = self.settings_provider.get_settings()
        key_id = public_key.key_id.hex()

        self._public_key_cache[key_id] = public_key
        self._public_key_storage.save_public_key(public_key)
        if key_id not in settings.public:
            settings.public.append(key_id)
            self.settings_provider.save_settings(settings)

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
