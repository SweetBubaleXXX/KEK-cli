import logging.config


def configure_logging(*, verbose: bool, quiet: bool) -> None:
    if verbose:
        log_level = "DEBUG"
    elif quiet:
        log_level = "CRITICAL"
    else:
        log_level = "INFO"

    logging_config = {
        "version": 1,
        "disable_existing_loggers": True,
        "formatters": {
            "verbose": {
                "format": "%(asctime)s [%(levelname)s] - %(name)s - %(message)s",
            },
            "simple": {
                "format": "%(message)s",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": log_level,
                "formatter": "verbose" if verbose else "simple",
                "stream": "ext://sys.stderr",
            },
        },
        "loggers": {
            "gnukek_cli": {
                "handlers": ["console"],
                "level": log_level,
                "propagate": False,
            },
        },
    }
    logging.config.dictConfig(logging_config)
