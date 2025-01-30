import click
from gnukek.constants import SUPPORTED_KEY_SIZES

from gnukek_cli.command_handlers.generate import GenerateKeyContext, GenerateKeyHandler
from gnukek_cli.constants import DEFAULT_KEY_SIZE


@click.command()
@click.option(
    "-s",
    "--key-size",
    type=click.Choice([str(size) for size in SUPPORTED_KEY_SIZES]),
    default=str(DEFAULT_KEY_SIZE),
    show_default=True,
    help="size of the key to generate",
)
@click.option("--password", type=str, help="password to use for the private key")
@click.option(
    "--prompt/--no-prompt",
    default=True,
    show_default=True,
    help="should prompt for password",
)
@click.option(
    "--save/--no-save",
    default=True,
    show_default=True,
    help="should save the key to storage or print to stdout",
)
def generate(key_size, password, prompt, save) -> None:
    """Generate new key pair."""

    context = GenerateKeyContext(
        key_size=int(key_size),  # type: ignore
        password=password.encode() if password else None,
        prompt_password=prompt if not password else False,
        save=save,
    )
    handle = GenerateKeyHandler(context)
    handle()
