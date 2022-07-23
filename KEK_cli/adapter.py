import logging
import sys
from argparse import Namespace
from functools import wraps
from getpass import getpass
from typing import Callable, Optional

from .backend import KeyManager


def exception_decorator(func: Callable):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except Exception:
            err_type, value, traceback = sys.exc_info()
            logging.error(value)
            logging.debug(f"{err_type.__name__}: {traceback.tb_frame}")
    return wrapper


def pinentry(attribute: str):
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(self, args: Namespace):
            if self.key_manager.is_encrypted(getattr(args, attribute)):
                logging.info("Enter passphrase for key")
                password = getpass()
            return func(self, args, password)
        return wrapper
    return decorator


class CliAdapter:
    def __init__(self, key_manager: KeyManager) -> None:
        self.key_manager = key_manager

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
        logging.debug(f"Key id: {id}")

    @exception_decorator
    @pinentry("key_id")
    def encrypt(self, args: Namespace, password: Optional[str] = None) -> None:
        for file in args.files:
            output_path = self.key_manager.encrypt(
                file.name,
                args.output_file,
                args.key_id,
                password
            )
            logging.info("Successfully encrypted file")
            logging.debug(f"Encrypted file: {output_path}")

    @exception_decorator
    @pinentry("key_id")
    def decrypt(self, args: Namespace, password: Optional[str] = None) -> None:
        for file in args.files:
            output_path = self.key_manager.decrypt(
                file.name,
                args.output_file,
                args.key_id,
                password,
            )
            logging.info("Successfully decrypted file")
            logging.debug(f"Decrypted file: {output_path}")

    @exception_decorator
    @pinentry("key_id")
    def sign(self, args: Namespace, password: Optional[str] = None) -> None:
        pass

    @exception_decorator
    @pinentry("key_id")
    def verify(self, args: Namespace, password: Optional[str] = None) -> None:
        pass

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
                                    args.output_file, password)
        logging.info("Successfully exported key")
