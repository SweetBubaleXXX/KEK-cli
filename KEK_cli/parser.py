import argparse

from KEK.hybrid import PrivateKEK

from ._version import __version__
from .adapter import CliAdapter
from .key_storage import key_storage

adapter = CliAdapter(key_storage)

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

info_parser = subparsers.add_parser(
    "info",
    help="show info about KEK algorithm"
)
info_parser.set_defaults(func=adapter.info)

list_parser = subparsers.add_parser("list", help="list keys")
list_parser.set_defaults(func=adapter.list_keys)

default_key_parser = subparsers.add_parser(
    "default",
    help="set default private key"
)
default_key_parser.set_defaults(func=adapter.set_default)

delete_parser = subparsers.add_parser(
    "delete",
    help="delete key"
)
delete_parser.set_defaults(func=adapter.delete_key)

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
sign_parser.set_defaults(func=adapter.sign)

verify_parser = subparsers.add_parser("verify", help="verify signature")
verify_parser.add_argument(
    "signature",
    type=argparse.FileType("r"),
    help="file with signature"
)
verify_parser.add_argument(
    "file",
    type=argparse.FileType("r"),
    help="original file"
)
verify_parser.set_defaults(func=adapter.verify)

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
export_parser.set_defaults(func=adapter.export_key)

for subparser in [encrypt_parser, decrypt_parser, sign_parser, export_parser]:
    subparser.add_argument(
        "-o",
        "--output",
        type=str,
        dest="output_file",
        metavar="FILENAME"
    )
    subparser.add_argument(
        "-r",
        "--replace",
        action="store_true",
        dest="overwrite",
        help="Overwrite file if exists"
    )

for subparser in [encrypt_parser, decrypt_parser, sign_parser, verify_parser]:
    subparser.add_argument(
        "-k",
        "--key",
        type=str,
        dest="key_id",
        help="id of a key to use"
    )

for subparser in [encrypt_parser, decrypt_parser]:
    subparser.add_argument(
        "--no-chunks",
        action="store_true",
        dest="no_chunk",
        help="load the whole file to RAM"
    )
    subparser.add_argument(
        "--chunk-size",
        default=1024*1024,
        type=int,
        dest="chunk_size",
        help=(
            f"(in bytes), must be multiple of {PrivateKEK.block_size//8}, "
            f"default - {1024*1024} bytes (1MB)"
        )
    )

for subparser in [delete_parser, default_key_parser, export_parser]:
    subparser.add_argument(
        "id",
        type=str
    )

for subparser in [encrypt_parser, decrypt_parser, sign_parser]:
    subparser.add_argument(
        "files",
        nargs="+",
        type=argparse.FileType("r"),
    )
