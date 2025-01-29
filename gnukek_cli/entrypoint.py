import click

from gnukek_cli.constants import DEFAULT_CONFIG_DIR
from gnukek_cli.container import Container


@click.command()
def main():
    container = Container()
    container.config.key_storage_path.from_env(
        "KEK_CONFIG_DIR", default=DEFAULT_CONFIG_DIR
    )


if __name__ == "__main__":
    main()
