import argparse
from KEK.hybrid import PrivateKEK

__version__ = "0.1.0"

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
generate_parser.set_defaults(func=lambda *x: print(x))

encrypt_parser = subparsers.add_parser("encrypt", help="encrypt file")
encrypt_parser.add_argument(
    "file",
    nargs="+",
    type=argparse.FileType("r"),
)
encrypt_parser.set_defaults(func=lambda *x: print(x))

decrypt_parser = subparsers.add_parser("decrypt", help="decrypt file")
decrypt_parser.set_defaults(func=lambda *x: print(x))

sign_parser = subparsers.add_parser("sign", help="sign file")
sign_parser.set_defaults(func=lambda *x: print(x))

verify_parser = subparsers.add_parser("verify", help="verify signature")
verify_parser.set_defaults(func=lambda *x: print(x))

import_parser = subparsers.add_parser("import", help="import key from file")
import_parser.set_defaults(func=lambda *x: print(x))

export_parser = subparsers.add_parser("export", help="export key to file")
export_parser.set_defaults(func=lambda *x: print(x))

for subparser in [encrypt_parser, sign_parser, export_parser]:
    subparser.add_argument(
        "-o",
        "--output",
        type=str,
        dest="filename"
    )

for subparser in [encrypt_parser, decrypt_parser, sign_parser, verify_parser]:
    subparser.add_argument(
        "-i",
        "--id",
        type=str,
        dest="key_id",
        help="id of a key to use"
    )
    subparser.add_argument(
        "-k",
        "--key-file",
        type=argparse.FileType("r"),
        dest="key_file",
        help="use key from specific file"
    )


def main():
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
