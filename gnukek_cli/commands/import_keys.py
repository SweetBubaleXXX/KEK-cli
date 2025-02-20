from io import BufferedReader

import click

from gnukek_cli.command_handlers.import_keys import ImportKeysContext, ImportKeysHandler


@click.command("import")
@click.argument("key_files", type=click.File("rb"), nargs=-1)
@click.option("--password", type=str, help="password to use for the private keys")
@click.option(
    "--prompt/--no-prompt",
    default=True,
    show_default=True,
    help="should prompt for password",
)
def import_keys(key_files: tuple[BufferedReader], password, prompt) -> None:
    """Import keys from files or stdin."""
    assert len(key_files)

    context = ImportKeysContext(
        key_files=key_files,
        password=password.encode() if password else None,
        prompt_password=prompt if not password else False,
    )
    handle = ImportKeysHandler(context)
    handle()
