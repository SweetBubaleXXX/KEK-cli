import click
from dependency_injector.wiring import Provide, inject
from gnukek.constants import LATEST_KEK_VERSION, SUPPORTED_KEY_SIZES

from gnukek_cli import __version__
from gnukek_cli.container import Container


@click.command()
@inject
def version(key_storage_path: str = Provide[Container.config.key_storage_path]) -> None:
    """Print version information."""
    click.echo(f"gnukek-cli {__version__}\n")
    click.echo(f"Latest KEK algorithm supported: {LATEST_KEK_VERSION}")
    click.echo(f"Config path: {key_storage_path}")

    supported_key_sizes = map(str, sorted(SUPPORTED_KEY_SIZES))
    click.echo(f"Supported key sizes: {', '.join(supported_key_sizes)}")
