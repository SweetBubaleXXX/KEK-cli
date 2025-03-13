import logging
import resource
from functools import wraps
from time import perf_counter
from typing import Any, Callable, ParamSpec

logger = logging.getLogger(__name__)

P = ParamSpec("P")


def measure(func: Callable[P, Any]) -> Callable[P, Any]:
    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
        time_start = perf_counter()

        try:
            func(*args, **kwargs)
        finally:
            time_stop = perf_counter()
            time_elapsed = time_stop - time_start

            logger.debug(f"Took {time_elapsed:.4f} seconds")

            mem_usage_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            mem_usage_mb = mem_usage_kb / 1024

            logger.debug(f"Memory usage: {mem_usage_mb:.2f} MB")

    return wrapper
