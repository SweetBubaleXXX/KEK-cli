import logging
import sys
from contextlib import contextmanager

from gnukek.exceptions import KekException

logger = logging.getLogger(__name__)


@contextmanager
def handle_exceptions():
    try:
        yield
    except KekException as e:
        logger.error(e)
        logger.debug(e, exc_info=True)
        sys.exit(1)
    except KeyNotFoundError as e:
        logger.error(e)
        logger.debug(e, exc_info=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred:\n{e}")
        logger.debug(e, exc_info=True)
        sys.exit(1)


class KeyNotFoundError(Exception):
    def __init__(self, key_id: str, *args: object) -> None:
        super().__init__(f"Key not found: {key_id}", *args)
