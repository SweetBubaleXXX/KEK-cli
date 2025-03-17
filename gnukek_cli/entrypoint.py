import os

import click

from gnukek_cli import commands
from gnukek_cli.constants import DEFAULT_CONFIG_DIR
from gnukek_cli.container import Container
from gnukek_cli.utils.exceptions import handle_exceptions
from gnukek_cli.utils.logger import configure_logging
from gnukek_cli.utils.monitoring import measure

try:
    import boto3
except ImportError:
    boto3 = None  # type: ignore


@click.group(
    commands=[
        commands.decrypt,
        commands.delete_key,
        commands.edit,
        commands.encrypt,
        commands.export,
        commands.generate,
        commands.import_keys,
        commands.list_keys,
        commands.sign,
        commands.verify,
        commands.version,
    ]
)
@click.option("-v", "--verbose", is_flag=True, help="use verbose logging")
@click.option("-q", "--quiet", is_flag=True, help="disable logging")
def cli(verbose: bool, quiet: bool) -> None:
    configure_logging(verbose=verbose, quiet=quiet)


@measure
def main():
    container = Container()
    container.config.key_storage_path.from_env(
        "KEK_CONFIG_DIR",
        default=DEFAULT_CONFIG_DIR,
        as_=os.path.expanduser,
    )

    if boto3:
        from gnukek_cli.extras.s3 import command_handlers
        from gnukek_cli.extras.s3.commands import s3_commands

        for command in s3_commands:
            cli.add_command(command)

        container.wire(packages=[command_handlers])

    with handle_exceptions():
        cli()


if __name__ == "__main__":
    main()
