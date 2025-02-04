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

    cli.add_command(commands.decrypt)
    cli.add_command(commands.delete_key)
    cli.add_command(commands.encrypt)
    cli.add_command(commands.export)
    cli.add_command(commands.generate)
    cli.add_command(commands.import_keys)
    cli.add_command(commands.list_keys)
    cli.add_command(commands.version)

    cli()


if __name__ == "__main__":
    main()
