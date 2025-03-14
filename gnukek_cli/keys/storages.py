import logging
from abc import ABCMeta, abstractmethod
from pathlib import Path

from gnukek.constants import SerializedKeyType
from gnukek.keys import KeyPair, PublicKey
from gnukek.utils import get_key_type

from gnukek_cli.constants import CONFIG_DIR_PERMISSIONS, KEY_FILE_PERMISSIONS
from gnukek_cli.utils.exceptions import KeyNotFoundError
from gnukek_cli.utils.passwords import PromptPasswordCallback

logger = logging.getLogger(__name__)


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


class _FileStorage:
    def __init__(self, base_path: str) -> None:
        self._base_path = Path(base_path)

    def ensure_folder_exists(self) -> None:
        self._base_path.mkdir(CONFIG_DIR_PERMISSIONS, parents=True, exist_ok=True)


class PublicKeyFileStorage(PublicKeyStorage, _FileStorage):
    def __init__(self, base_path: str) -> None:
        self._base_path = Path(base_path)

    def read_public_key(self, key_id: str) -> PublicKey:
        key_path = self._get_key_path(key_id)

        if not key_path.is_file():
            raise KeyNotFoundError(key_id)

        with open(key_path, "rb") as key_file:
            serialized_key = key_file.read()

        logger.debug(f"Read public key: {key_id}")
        return PublicKey.load(serialized_key)

    def save_public_key(self, public_key: PublicKey) -> None:
        key_path = self._get_key_path(public_key.key_id.hex())

        serialized_key = public_key.serialize()
        self.ensure_folder_exists()
        key_path.write_bytes(serialized_key)
        key_path.chmod(KEY_FILE_PERMISSIONS)
        logger.debug(f"Saved public key: {public_key.key_id.hex()}")

    def delete_public_key(self, key_id: str) -> None:
        key_path = self._get_key_path(key_id)

        if not key_path.is_file():
            raise KeyNotFoundError(key_id)

        key_path.unlink()
        logger.debug(f"Deleted public key: {key_id}")

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


class PrivateKeyFileStorage(PrivateKeyStorage, _FileStorage):
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

        logger.debug(f"Read private key: {key_id}")
        return KeyPair.load(serialized_key, password=password)

    def save_private_key(
        self, key_pair: KeyPair, password: bytes | None = None
    ) -> None:
        key_path = self._get_key_path(key_pair.key_id.hex())

        serialized_key = key_pair.serialize(password=password)

        self.ensure_folder_exists()
        key_path.write_bytes(serialized_key)
        key_path.chmod(KEY_FILE_PERMISSIONS)
        logger.debug(f"Saved private key: {key_pair.key_id.hex()}")

    def delete_private_key(self, key_id: str) -> None:
        key_path = self._get_key_path(key_id)

        if not key_path.is_file():
            logger.error(f"Private key not found: {key_id}")
            raise KeyNotFoundError(key_id)

        key_path.unlink()
        logger.debug(f"Deleted private key: {key_id}")

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


def get_public_key_filename(key_id: str) -> str:
    return f"{key_id}.pub.kek"


def get_private_key_filename(key_id: str) -> str:
    return f"{key_id}.kek"
