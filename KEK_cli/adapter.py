import logging
from argparse import Namespace
from getpass import getpass

from .backend import KeyManager


class CliAdapter:
    def __init__(self, key_manager: KeyManager) -> None:
        self.key_manager = key_manager

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

    def encrypt(self, args: Namespace) -> None:
        password = None
        if self.key_manager.is_encrypted(args.key_id):
            logging.info("Enter passphrase for key")
            password = getpass()
        output_path = self.key_manager.encrypt(
            args.file.name,
            args.output_file,
            args.key_id,
            password,
        )
        logging.info("Successfully encrypted file")
        logging.debug(f"Encrypted file: {output_path}")

    def decrypt(self, args: Namespace) -> None:
        password = None
        if self.key_manager.is_encrypted(args.key_id):
            logging.info("Enter passphrase for key")
            password = getpass()
        output_path = self.key_manager.decrypt(
            args.file.name,
            args.output_file,
            args.key_id,
            password,
        )
        logging.info("Successfully decrypted file")
        logging.debug(f"Decrypted file: {output_path}")

    def sign(self, args: Namespace) -> None:
        pass

    def verify(self, args: Namespace) -> None:
        pass

    def import_key(self, args: Namespace) -> None:
        password = None
        if self.key_manager.is_encrypted(path=args.file.name):
            logging.info("Enter passphrase for key")
            password = getpass()
        id = self.key_manager.import_key(args.file.name, password)
        logging.info("Successfully imported key")
        logging.info(f"Key id: {id}")

    def export_key(self, args: Namespace) -> None:
        password = None
        if self.key_manager.is_encrypted(args.id):
            logging.info("Enter passphrase for key")
            password = getpass()
        self.key_manager.export_key(args.id, args.public,
                                    args.output_file, password)
        logging.info("Successfully exported key")
