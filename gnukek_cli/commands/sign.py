from io import FileIO

import click
from gnukek.constants import CHUNK_LENGTH


@click.command()
@click.argument("input_file", type=click.File("rb"))
@click.argument("output_file", type=click.File("wb"), default="-")
@click.option("-k", "--key", help="key id to use")
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
    pass
