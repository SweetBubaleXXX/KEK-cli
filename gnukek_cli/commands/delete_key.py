import click

from gnukek_cli.command_handlers.delete_key import DeleteKeyContext, DeleteKeyHandler
from gnukek_cli.utils.completions import KeyIdParam


@click.command("delete")
@click.argument("key_ids", type=KeyIdParam(), nargs=-1)
@click.option(
    "--keep-public",
    is_flag=True,
    default=False,
    help="do not remove public key",
)
def delete_key(key_ids, keep_public):
    """Remove keys from storage."""
    assert len(key_ids)

    context = DeleteKeyContext(key_ids=key_ids, keep_public=keep_public)
    handle = DeleteKeyHandler(context)
    handle()
