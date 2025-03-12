from io import FileIO

import click

from gnukek_cli.extras.s3.command_handlers.download import (
    DownloadContext,
    DownloadHandler,
)
from gnukek_cli.extras.s3.helpers import parse_s3_object_location


@click.command("s3-download")
@click.argument("file_location")
@click.argument("output_file", type=click.File("wb"), default="-")
@click.pass_context
def s3_download(
    ctx: click.Context,
    file_location,
    output_file: FileIO,
) -> None:
    """Download and decrypt file from s3 bucket."""
    try:
        bucket_name, object_name = parse_s3_object_location(file_location)
    except ValueError:
        ctx.fail("File location must be in the format 'bucket/object'")

    context = DownloadContext(
        bucket_name=bucket_name,
        object_name=object_name,
        output_file=output_file,
    )
    handle = DownloadHandler(context)
    handle()
