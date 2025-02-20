import click

from gnukek_cli.command_handlers.export import ExportContext, ExportHandler


@click.command()
@click.argument("key_id")
@click.argument("file", type=click.File("wb"))
@click.option("--public", is_flag=True, help="export public key")
@click.option(
    "--prompt/--no-prompt",
    default=True,
    show_default=True,
    help="should prompt for password",
)
def export(key_id, file, public, prompt) -> None:
    """Export key."""

    context = ExportContext(
        key_id=key_id,
        file=file,
        public=public,
        prompt_password=prompt,
    )
    handle = ExportHandler(context)
    handle()
