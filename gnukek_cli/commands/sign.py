from io import FileIO

import click
from gnukek.constants import CHUNK_LENGTH

from gnukek_cli.command_handlers.sign import SignContext, SignHandler
from gnukek_cli.utils.completions import KeyIdParam


@click.command()
@click.argument("input_file", type=click.File("rb"))
@click.argument("output_file", type=click.File("wb"), default="-")
@click.option("-k", "--key", type=KeyIdParam(), help="key id to use")
@click.option(
    "--chunk-size",
    type=int,
    default=CHUNK_LENGTH,
    show_default=True,
    help="chunk size in bytes, use 0 to process file in one go",
)
def sign(
    input_file: FileIO,
    output_file: FileIO,
    key,
    chunk_size,
) -> None:
    """Create signature."""
    context = SignContext(
        input_file=input_file,
        output_file=output_file,
        key_id=key,
        chunk_length=chunk_size,
    )

    handler = SignHandler(context)
    handler()
