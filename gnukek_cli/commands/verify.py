from io import FileIO

import click
from gnukek.constants import CHUNK_LENGTH

from gnukek_cli.command_handlers.verify import VerifyContext, VerifyHandler
from gnukek_cli.utils.completions import KeyIdParam


@click.command()
@click.argument("signature_file", type=click.File("rb"))
@click.argument("original_file", type=click.File("rb"))
@click.option("-k", "--key", type=KeyIdParam(), help="key id to use")
@click.option(
    "--chunk-size",
    type=int,
    default=CHUNK_LENGTH,
    show_default=True,
    help="chunk size in bytes, use 0 to process file in one go",
)
def verify(signature_file: FileIO, original_file: FileIO, key, chunk_size):
    """Verify signature."""
    context = VerifyContext(
        signature_file=signature_file,
        original_file=original_file,
        key_id=key,
        chunk_length=chunk_size,
    )

    handler = VerifyHandler(context)
    handler()
