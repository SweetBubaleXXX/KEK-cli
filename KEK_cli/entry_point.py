import logging
from .parser import parser


def main():
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    args.func(args)
