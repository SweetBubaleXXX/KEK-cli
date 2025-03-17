from io import BytesIO
from pathlib import Path

import click
from gnukek.constants import LATEST_KEK_VERSION

from gnukek_cli.command_handlers.decrypt import DecryptContext, DecryptHandler
from gnukek_cli.command_handlers.encrypt import EncryptContext, EncryptHandler
from gnukek_cli.utils.completions import KeyIdParam

DEFAULT_FILE_EXTENSION = ".md"


@click.command()
@click.argument(
    "file_path",
    type=click.Path(dir_okay=False, path_type=Path),
)
@click.option("-k", "--key", type=KeyIdParam(), help="key id to use for encryption")
@click.option(
    "--version",
    type=int,
    default=LATEST_KEK_VERSION,
    show_default=True,
    help="algorithm version to use",
)
@click.option("--extension", help="file extension to use when opening file")
def edit(file_path: Path, key, version, extension: str | None) -> None:
    """Edit encrypted file."""

    decrypted_content = BytesIO()

    if file_path.exists():
        with open(file_path, "rb") as file:
            decryption_context = DecryptContext(
                input_file=file, output_file=decrypted_content
            )
            handle_decryption = DecryptHandler(decryption_context)
            handle_decryption()

    editor_extension = extension or file_path.suffix or DEFAULT_FILE_EXTENSION
    edited_text = click.edit(decrypted_content.getvalue(), extension=editor_extension)

    if edited_text:
        with open(file_path, "wb") as file:
            encryption_context = EncryptContext(
                input_file=BytesIO(edited_text),
                output_file=file,
                key_id=key,
                version=version,
            )
            handle_encryption = EncryptHandler(encryption_context)
            handle_encryption()
