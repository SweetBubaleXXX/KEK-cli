import logging
from collections.abc import Iterable
from dataclasses import dataclass

from dependency_injector.wiring import Provide, inject

from gnukek_cli.container import Container
from gnukek_cli.keys.provider import KeyProvider

logger = logging.getLogger(__name__)


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
        key_provider: KeyProvider = Provide[Container.key_provider],
    ) -> None:
        self.context = context
        self._key_provider = key_provider

    def __call__(self) -> None:
        for key_id in self.context.key_ids:
            logger.debug(f"Removing key: {key_id}")
            self._key_provider.remove_private_key(key_id)
            logger.info(f"Private key removed: {key_id}")
            if not self.context.keep_public:
                self._key_provider.remove_public_key(key_id)
                logger.info(f"Public key removed: {key_id}")
