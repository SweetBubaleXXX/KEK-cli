from io import BytesIO, FileIO
from pathlib import Path

import click
from gnukek.constants import LATEST_KEK_VERSION

from gnukek_cli.command_handlers.decrypt import DecryptContext, DecryptHandler
from gnukek_cli.command_handlers.encrypt import EncryptContext, EncryptHandler
from gnukek_cli.utils.completions import KeyIdParam

DEFAULT_FILE_EXTENSION = ".md"


@click.command()
@click.argument("file", type=click.File("rb+"))
@click.option("-k", "--key", type=KeyIdParam(), help="key id to use for encryption")
@click.option(
    "--version",
    type=int,
    default=LATEST_KEK_VERSION,
    show_default=True,
    help="algorithm version to use",
)
@click.option("--extension", help="file extension to use when opening file")
def edit(file: FileIO, key, version, extension: str | None) -> None:
    """Edit encrypted file."""

    decrypted_buffer = BytesIO()

    decryption_context = DecryptContext(input_file=file, output_file=decrypted_buffer)
    handle_decryption = DecryptHandler(decryption_context)

    handle_decryption()

    file_path = Path(file.name)
    editor_extension = extension or file_path.suffix or DEFAULT_FILE_EXTENSION

    edited_text = click.edit(decrypted_buffer.getvalue(), extension=editor_extension)

    if edited_text:
        encryption_context = EncryptContext(
            input_file=BytesIO(edited_text),
            output_file=file,
            key_id=key,
            version=version,
        )
        handle_encryption = EncryptHandler(encryption_context)

        file.seek(0)
        file.truncate(0)
        handle_encryption()
