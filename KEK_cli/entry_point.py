from .parser import parser


def main():
    args = parser.parse_args()
    verbose = args.verbose
    args.func(args)
