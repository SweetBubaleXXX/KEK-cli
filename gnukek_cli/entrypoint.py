import os

import click

from gnukek_cli import commands
from gnukek_cli.constants import DEFAULT_CONFIG_DIR
from gnukek_cli.container import Container
from gnukek_cli.exceptions import handle_exceptions
from gnukek_cli.logger import configure_logging


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="use verbose logging")
@click.option("-q", "--quiet", is_flag=True, help="disable logging")
def cli(verbose: bool, quiet: bool) -> None:
    configure_logging(verbose=verbose, quiet=quiet)


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
    cli.add_command(commands.sign)
    cli.add_command(commands.verify)
    cli.add_command(commands.version)

    with handle_exceptions():
        cli()


if __name__ == "__main__":
    main()
