import logging
import os
import sys
from argparse import Namespace
from functools import wraps
from getpass import getpass
from typing import Callable, Optional

from .backend import KeyManager, get_full_path


def exception_decorator(func: Callable):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except Exception:
            err_type, value, traceback = sys.exc_info()
            logging.error(value)
            logging.debug(f"{err_type.__name__}: {traceback.tb_frame}")
            if err_type == FileExistsError:
                logging.info("To overwrite use '-r' option")
    return wrapper


def pinentry(attribute: str):
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(self, args: Namespace):
            password = None
            if self.key_manager.is_encrypted(getattr(args, attribute)):
                logging.info("Enter passphrase for key")
                password = getpass()
            return func(self, args, password)
        return wrapper
    return decorator


def should_overwrite(path: str) -> bool:
    logging.info(f"File '{path}' exists")
    answer = input("Overwrite? [Y/n] ")
    return not answer.strip() or answer.lower() == "y"


class CliAdapter:
    def __init__(self, key_manager: KeyManager) -> None:
        self.key_manager = key_manager

    @exception_decorator
    def list_keys(self, args: Namespace) -> None:
        logging.info(f"Default: {self.key_manager.default_key}")
        logging.info("Private: \n\t{}".format(
            "\n\t".join(self.key_manager.private_keys) or "empty"))
        logging.info("Public: \n\t{}".format(
            "\n\t".join(self.key_manager.public_keys) or "empty"))

    @exception_decorator
    def set_default(self, args: Namespace) -> None:
        self.key_manager.set_default(args.id)

    @exception_decorator
    def delete_key(self, args: Namespace) -> None:
        self.key_manager.delete_key(args.id)
        logging.info("Successfully deleted key")

    @exception_decorator
    def generate(self, args: Namespace) -> None:
        logging.info(
            "Choose passphrase for key or leave empty for no passphrase")
        password = getpass()
        if password:
            repeated_password = getpass("Repeat password: ")
            if password != repeated_password:
                return logging.error("Passwords don't match")
        id = self.key_manager.generate(args.key_size, password or None)
        logging.info("Successfully created new key")
        logging.info(f"Key id: {id}")

    @exception_decorator
    @pinentry("key_id")
    def encrypt(self, args: Namespace, password: Optional[str] = None) -> None:
        for file in args.files:
            overwrite = args.overwrite
            if (not overwrite and args.output_file and
                    os.path.isfile(get_full_path(args.output_file))):
                overwrite = should_overwrite(args.output_file)
                if not overwrite:
                    logging.debug(f"File '{args.output_file}' skipped")
                    continue
            output_path = self.key_manager.encrypt(
                file.name,
                args.output_file,
                args.key_id,
                password,
                overwrite
            )
            logging.info("Successfully encrypted file")
            logging.debug(f"Encrypted file: {output_path}")

    @exception_decorator
    @pinentry("key_id")
    def decrypt(self, args: Namespace, password: Optional[str] = None) -> None:
        for file in args.files:
            overwrite = args.overwrite
            if (not overwrite and args.output_file and
                    os.path.isfile(get_full_path(args.output_file))):
                overwrite = should_overwrite(args.output_file)
                if not overwrite:
                    logging.debug(f"File '{args.output_file}' skipped")
                    continue
            output_path = self.key_manager.decrypt(
                file.name,
                args.output_file,
                args.key_id,
                password,
                overwrite
            )
            logging.info("Successfully decrypted file")
            logging.debug(f"Decrypted file: {output_path}")

    @exception_decorator
    @pinentry("key_id")
    def sign(self, args: Namespace, password: Optional[str] = None) -> None:
        for file in args.files:
            overwrite = args.overwrite
            if (not overwrite and args.output_file and
                    os.path.isfile(get_full_path(args.output_file))):
                overwrite = should_overwrite(args.output_file)
                if not overwrite:
                    logging.debug(f"File '{args.output_file}' skipped")
                    continue
            output_path = self.key_manager.sign(
                file.name,
                args.output_file,
                args.key_id,
                password,
                overwrite
            )
            logging.info("Successfully signed file")
            logging.debug(f"Signature file: {output_path}")

    @exception_decorator
    @pinentry("key_id")
    def verify(self, args: Namespace, password: Optional[str] = None) -> None:
        verified = self.key_manager.verify(
            args.signature.name,
            args.file.name,
            args.key_id,
            password
        )
        if verified:
            logging.info("Verified")
        else:
            logging.info("Verification failed")

    @exception_decorator
    def import_key(self, args: Namespace,
                   password: Optional[str] = None) -> None:
        if self.key_manager.is_encrypted(path=args.file.name):
            logging.info("Enter passphrase for key")
            password = getpass()
        id = self.key_manager.import_key(args.file.name, password)
        logging.info("Successfully imported key")
        logging.info(f"Key id: {id}")

    @exception_decorator
    @pinentry("id")
    def export_key(self, args: Namespace,
                   password: Optional[str] = None) -> None:
        self.key_manager.export_key(args.id, args.public,
                                    args.output_file, password, args.overwrite)
        logging.info("Successfully exported key")
