import click

from gnukek_cli.command_handlers.list_keys import ListKeysHandler


@click.command("list")
def list_keys() -> None:
    """List saved keys."""
    handle = ListKeysHandler()
    handle()
