import argparse

from KEK.hybrid import PrivateKEK

from ._version import __version__
from .key_manager import key_manager
from .adapter import CliAdapter

adapter = CliAdapter(key_manager)

parser = argparse.ArgumentParser(
    description="CLI for Kinetic Encryption Key"
)

parser.add_argument(
    "--version",
    action="version",
    version=f"v{__version__}"
)

parser.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    help="show verbose output"
)

subparsers = parser.add_subparsers(
    help="sub-commands",
    required=True
)

generate_parser = subparsers.add_parser("generate", help="generate key")
generate_parser.add_argument(
    "-s",
    "--size",
    default=PrivateKEK.default_size,
    type=int,
    choices=PrivateKEK.key_sizes,
    dest="key_size",
    help=f"size of a key, default - {PrivateKEK.default_size}",
)
generate_parser.set_defaults(func=adapter.generate)

encrypt_parser = subparsers.add_parser("encrypt", help="encrypt file")
encrypt_parser.set_defaults(func=adapter.encrypt)

decrypt_parser = subparsers.add_parser("decrypt", help="decrypt file")
decrypt_parser.set_defaults(func=adapter.decrypt)

sign_parser = subparsers.add_parser("sign", help="sign file")
sign_parser.set_defaults(func=lambda *x: print(x))

verify_parser = subparsers.add_parser("verify", help="verify signature")
verify_parser.set_defaults(func=lambda *x: print(x))

import_parser = subparsers.add_parser("import", help="import key from file")
import_parser.add_argument(
    "file",
    type=argparse.FileType("r"),
    help="file with key"
)
import_parser.set_defaults(func=adapter.import_key)

export_parser = subparsers.add_parser("export", help="export key to file")
export_parser.add_argument(
    "--public",
    action="store_true",
    dest="public",
    help="export public key"
)
export_parser.add_argument(
    "id",
    type=str
)
export_parser.set_defaults(func=adapter.export_key)

for subparser in [encrypt_parser, decrypt_parser, sign_parser, export_parser]:
    subparser.add_argument(
        "-o",
        "--output",
        type=str,
        dest="output_file",
        metavar="FILENAME"
    )

for subparser in [encrypt_parser, decrypt_parser, sign_parser, verify_parser]:
    subparser.add_argument(
        "-k",
        "--key",
        type=str,
        dest="key_id",
        help="id of a key to use"
    )

for subparser in [encrypt_parser, decrypt_parser, sign_parser, verify_parser]:
    subparser.add_argument(
        "files",
        nargs="+",
        type=argparse.FileType("r"),
    )
