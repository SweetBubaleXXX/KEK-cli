import os

import click

from gnukek_cli import commands
from gnukek_cli.constants import DEFAULT_CONFIG_DIR
from gnukek_cli.container import Container


@click.group()
def cli() -> None:
    pass


def main():
    container = Container()
    container.config.key_storage_path.from_env(
        "KEK_CONFIG_DIR",
        default=DEFAULT_CONFIG_DIR,
        as_=os.path.expanduser,
    )

    cli.add_command(commands.generate)

    cli()


if __name__ == "__main__":
    main()
