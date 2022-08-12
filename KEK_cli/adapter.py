import logging
import os
import sys
import traceback
from argparse import Namespace
from functools import wraps
from getpass import getpass
from typing import Callable, Optional

from KEK.hybrid import PrivateKEK

from .backend import KeyStorage
from .backend.files import EncryptedFile, File, KeyFile, SignatureFile


def exception_decorator(func: Callable):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except Exception:
            err_type, value = sys.exc_info()[:2]
            logging.error(value)
            logging.debug(traceback.format_exc())
            if err_type == FileExistsError:
                logging.info("To overwrite use '-r' option")
            sys.exit(1)
    return wrapper


def pinentry(attribute: str):
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(self, args: Namespace):
            password = None
            if self.key_storage.export(
                getattr(args, attribute) or self.key_storage.default_key
            ).is_encrypted:
                logging.info("Enter password for key")
                password = getpass()
            return func(self, args, password)
        return wrapper
    return decorator


class CliAdapter:
    def __init__(self, key_storage: KeyStorage):
        self.key_storage = key_storage

    def __should_overwrite(self, path: str) -> bool:
        logging.info(f"File '{path}' exists")
        answer = input("Overwrite? [Y/n] ").strip()
        return not answer or answer.lower() == "y"

    @exception_decorator
    def info(self, args: Namespace):
        logging.info(f"KEK algorithm version: {PrivateKEK.version}")
        logging.info(f"Encryption algorithm: {PrivateKEK.algorithm}")
        logging.info(f"Avaliable key sizes: {PrivateKEK.key_sizes}")
        logging.info(f"Config location: {self.key_storage.config_path}")

    @exception_decorator
    def list_keys(self, args: Namespace):
        logging.info(f"Default: {self.key_storage.default_key}")
        logging.info("Private: \n\t{}".format(
            "\n\t".join(self.key_storage.private_keys) or "No keys"))
        logging.info("Public: \n\t{}".format(
            "\n\t".join(self.key_storage.public_keys) or "No keys"))

    @exception_decorator
    def set_default(self, args: Namespace):
        self.key_storage.default = args.id

    @exception_decorator
    def delete_key(self, args: Namespace):
        self.key_storage.remove(args.id)
        logging.info("Successfully deleted key")

    @exception_decorator
    def generate(self, args: Namespace):
        logging.info(
            "Choose password for key or leave empty for no password")
        password = getpass()
        if password:
            repeated_password = getpass("Repeat password: ")
            if password != repeated_password:
                raise ValueError("Passwords don't match")
        key = PrivateKEK.generate(args.key_size)
        id = self.key_storage.add(key, password or None)
        logging.info("Successfully created new key")
        logging.info(f"Key id: {id}")

    @exception_decorator
    @pinentry("key_id")
    def encrypt(self, args: Namespace, password: Optional[str] = None):
        for file in args.files:
            if (not args.overwrite and args.output_file
                    and os.path.isfile(args.output_file)):
                overwrite = self.__should_overwrite(args.output_file)
            else:
                overwrite = args.overwrite
            input_file = File(file.name, overwrite)
            output_path = args.output_file or input_file.output_path
            output_file = EncryptedFile(output_path, overwrite)
            key = self.key_storage.get(
                args.key_id or self.key_storage.default_key,
                password
            )
            encrypted_bytes = input_file.encrypt(key)
            output_file.write(encrypted_bytes)
        logging.info("Successfully encrypted file")

    @exception_decorator
    @pinentry("key_id")
    def decrypt(self, args: Namespace, password: Optional[str] = None):
        self.__multifile_operation(self.key_storage.decrypt, args,
                                   password, "Successfully decrypted file")

    @exception_decorator
    @pinentry("key_id")
    def sign(self, args: Namespace, password: Optional[str] = None):
        self.__multifile_operation(self.key_storage.sign, args,
                                   password, "Successfully signed file")

    @exception_decorator
    @pinentry("key_id")
    def verify(self, args: Namespace, password: Optional[str] = None):
        verified = self.key_storage.verify(
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
                   password: Optional[str] = None):
        if self.key_storage.is_encrypted(path=args.file.name):
            logging.info("Enter passphrase for key")
            password = getpass()
        id = self.key_storage.import_key(args.file.name, password)
        logging.info("Successfully imported key")
        logging.info(f"Key id: {id}")

    @exception_decorator
    @pinentry("id")
    def export_key(self, args: Namespace,
                   password: Optional[str] = None):
        self.key_storage.export_key(args.id, args.public,
                                    args.output_file, password, args.overwrite)
        logging.info("Successfully exported key")
