import click

from gnukek_cli.command_handlers.version import VersionHandler


@click.command()
def version() -> None:
    """Print version information."""
    handle = VersionHandler()
    handle()
