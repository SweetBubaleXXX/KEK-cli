import click


@click.command("s3-download")
@click.argument("file_location")
@click.argument("output_file", type=click.File("wb"), default="-")
def s3_download(
    ctx: click.Context,
) -> None:
    """Download and decrypt file from s3 bucket."""
    pass
