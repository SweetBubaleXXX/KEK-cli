from io import FileIO

import click
from gnukek.constants import LATEST_KEK_VERSION

from gnukek_cli.extras.s3.command_handlers.upload import UploadContext, UploadHandler
from gnukek_cli.extras.s3.helpers import parse_s3_object_location
from gnukek_cli.utils.completions import KeyIdParam


@click.command("s3-upload")
@click.argument("input_file", type=click.File("rb"))
@click.argument("file_location")
@click.option("-k", "--key", type=KeyIdParam(), help="key id to use")
@click.option("--no-chunk", is_flag=True, help="disable chunk encryption")
@click.option(
    "--version",
    type=int,
    default=LATEST_KEK_VERSION,
    show_default=True,
    help="algorithm version to use",
)
@click.pass_context
def s3_upload(
    ctx: click.Context,
    input_file: FileIO,
    file_location,
    key,
    no_chunk,
    version,
) -> None:
    """Encrypt and upload file to s3 bucket."""
    try:
        bucket_name, object_name = parse_s3_object_location(file_location)
    except ValueError:
        ctx.fail("File location must be in the format 'bucket/object'")

    context = UploadContext(
        input_file=input_file,
        bucket_name=bucket_name,
        object_name=object_name,
        key_id=key,
        no_chunk=no_chunk,
        version=version,
    )
    handle = UploadHandler(context)
    handle()
