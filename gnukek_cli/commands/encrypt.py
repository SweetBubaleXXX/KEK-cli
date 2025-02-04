from io import BufferedReader, BufferedWriter

import click
from gnukek.constants import CHUNK_LENGTH, LATEST_KEK_VERSION

from gnukek_cli.command_handlers.encrypt import EncryptContext, EncryptHandler


@click.command("")
@click.argument("input_file", type=click.File("rb"))
@click.argument("output_file", type=click.File("wb"))
@click.option("-k", "--key", help="key id to use")
@click.option(
    "--chunk-size",
    type=int,
    default=CHUNK_LENGTH,
    show_default=True,
    help="chunk size in bytes, use 0 to disable chunk encryption",
)
@click.option(
    "--version",
    type=int,
    default=LATEST_KEK_VERSION,
    show_default=True,
    help="algorithm version to use",
)
def encrypt(
    input_file: BufferedReader,
    output_file: BufferedWriter,
    key,
    chunk_size,
    version,
) -> None:
    """Encrypt single file."""
    context = EncryptContext(
        input_file=input_file,
        output_file=output_file,
        key_id=key,
        chunk_length=chunk_size,
        version=version,
    )
    handle = EncryptHandler(context)
    handle()
