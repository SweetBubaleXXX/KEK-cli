from io import FileIO
from pathlib import Path

import click
from gnukek.constants import CHUNK_LENGTH

from gnukek_cli.command_handlers.decrypt import DecryptContext, DecryptHandler


@click.command()
@click.argument("input_file", type=click.File("rb"))
@click.argument("output_file", type=click.File("wb"), default="-")
@click.option(
    "--chunk-size",
    type=int,
    default=CHUNK_LENGTH,
    show_default=True,
    help="chunk size in bytes, use 0 to disable chunk encryption",
)
def decrypt(
    input_file: FileIO,
    output_file: FileIO,
    chunk_size,
):
    """Decrypt single file."""

    is_inplace_decryption = (
        Path(input_file.name).resolve() == Path(output_file.name).resolve()
    )

    context = DecryptContext(
        input_file=input_file,
        output_file=output_file,
        chunk_length=chunk_size if not is_inplace_decryption else 0,
    )
    handle = DecryptHandler(context)
    handle()
