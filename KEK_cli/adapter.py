import logging
import os
import sys
import traceback
from argparse import Namespace
from functools import wraps
from getpass import getpass
from typing import Callable, Optional, Union

from KEK.hybrid import PrivateKEK, PublicKEK

from .backend import KeyStorage
from .backend.files import EncryptedFile, File, KeyFile, SignatureFile


def handle_exception(func: Callable):
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

    def __should_overwrite(self, args: Namespace) -> bool:
        if (not args.overwrite and args.output_file
                and os.path.isfile(args.output_file)):
            return self.__ask_overwrite(args.output_file)
        return args.overwrite

    def __ask_overwrite(self, path: str) -> bool:
        logging.info("File '%s' exists", path)
        answer = input("Overwrite? [Y/n] ").strip()
        return not answer or answer.lower() == "y"

    def __encrypt_chunks(
        self,
        key: Union[PrivateKEK, PublicKEK],
        input_file: File,
        output_file: EncryptedFile,
        chunk_length: int
    ):
        with (
            input_file.open("rb") as input_stream,
            output_file.open("wb") as output_stream
        ):
            for chunk in key.encrypt_chunks(input_stream, chunk_length):
                output_stream.write(chunk)

    def __decrypt_chunks(
        self,
        key: PrivateKEK,
        input_file: EncryptedFile,
        output_file: File,
        chunk_length: int
    ):
        with (
            input_file.open("rb") as input_stream,
            output_file.open("wb") as output_stream
        ):
            for chunk in key.decrypt_chunks(input_stream, chunk_length):
                output_stream.write(chunk)

    @handle_exception
    def info(self, args: Namespace):
        logging.info("KEK algorithm version: %s", PrivateKEK.version)
        logging.info("Encryption algorithm: %s", PrivateKEK.algorithm)
        logging.info("Avaliable key sizes: %s", PrivateKEK.key_sizes)
        logging.info("Config location: %s", self.key_storage.config_path)

    @handle_exception
    def list_keys(self, args: Namespace):
        logging.info("Default: %s", self.key_storage.default_key)
        logging.info("Private: \n\t%s",
                     "\n\t".join(self.key_storage.private_keys) or "No keys")
        logging.info("Public: \n\t%s",
                     "\n\t".join(self.key_storage.public_keys) or "No keys")

    @handle_exception
    def set_default(self, args: Namespace):
        self.key_storage.default_key = args.id

    @handle_exception
    def delete_key(self, args: Namespace):
        self.key_storage.remove(args.id)
        logging.info("Successfully deleted key")

    @handle_exception
    def generate(self, args: Namespace):
        logging.info(
            "Choose password for key or leave empty for no password")
        password = getpass()
        if password:
            repeated_password = getpass("Repeat password: ")
            if password != repeated_password:
                raise ValueError("Passwords don't match")
        key = PrivateKEK.generate(args.key_size)
        key_id = self.key_storage.add(key, password or None)
        logging.info("Successfully created new key")
        logging.info("Key id: %s", key_id)

    @handle_exception
    @pinentry("key_id")
    def encrypt(self, args: Namespace, password: Optional[str] = None):
        for file in args.files:
            overwrite = self.__should_overwrite(args)
            input_file = File(file.name, overwrite)
            output_path = args.output_file or input_file.output_path
            output_file = EncryptedFile(output_path, overwrite)
            key = self.key_storage.get(
                args.key_id or self.key_storage.default_key,
                password
            )
            if args.no_chunk:
                encrypted_bytes = input_file.encrypt(key)
                output_file.write(encrypted_bytes)
            elif input_file == output_file:
                raise ValueError
            else:
                self.__encrypt_chunks(
                    key,
                    input_file,
                    output_file,
                    args.chunk_size
                )
            logging.info("Successfully encrypted file '%s'", file.name)

    @handle_exception
    @pinentry("key_id")
    def decrypt(self, args: Namespace, password: Optional[str] = None):
        for file in args.files:
            overwrite = self.__should_overwrite(args)
            input_file = EncryptedFile(file.name, overwrite)
            output_path = args.output_file or input_file.output_path
            output_file = File(output_path, overwrite)
            key = self.key_storage.get(
                args.key_id or self.key_storage.default_key,
                password
            )
            if args.no_chunk:
                decrypted_bytes = input_file.decrypt(key)
                output_file.write(decrypted_bytes)
            elif input_file == output_file:
                raise ValueError
            else:
                self.__decrypt_chunks(
                    key,
                    input_file,
                    output_file,
                    args.chunk_size
                )
            logging.info("Successfully decrypted file '%s'", file.name)

    @handle_exception
    @pinentry("key_id")
    def sign(self, args: Namespace, password: Optional[str] = None):
        for file in args.files:
            overwrite = self.__should_overwrite(args)
            input_file = File(file.name, overwrite)
            output_path = args.output_file or input_file.output_path
            output_file = SignatureFile(output_path, overwrite)
            key = self.key_storage.get(
                args.key_id or self.key_storage.default_key,
                password
            )
            signature_bytes = input_file.sign(key)
            output_file.write(signature_bytes)
            logging.info("Successfully signed file '%s'", file.name)

    @handle_exception
    @pinentry("key_id")
    def verify(self, args: Namespace, password: Optional[str] = None):
        signature_file = SignatureFile(args.signature.name)
        original_file = File(args.file.name)
        key = self.key_storage.get(
            args.key_id or self.key_storage.default_key,
            password
        )
        verified = signature_file.verify(key, original_file.read())
        if verified:
            logging.info("Verified")
        else:
            logging.info("Verification failed")

    @handle_exception
    def import_key(self, args: Namespace, password: Optional[str] = None):
        key_file = KeyFile(args.file.name)
        if key_file.is_encrypted:
            logging.info("Enter password for key")
            password = getpass()
        encoded_password = self.key_storage.encode_password(password)
        serialized_bytes = key_file.load(encoded_password)
        key_id = self.key_storage.add(serialized_bytes)
        logging.info("Successfully imported key")
        logging.info("Key id: %s", key_id)

    @handle_exception
    @pinentry("id")
    def export_key(self, args: Namespace, password: Optional[str] = None):
        key_object = self.key_storage.get(args.id, password)
        if args.public and isinstance(key_object, PrivateKEK):
            key_object = key_object.public_key
        output_file = KeyFile(f"{args.id}.kek")
        encoded_password = self.key_storage.encode_password(password)
        output_file.export(key_object, encoded_password)
        logging.info("Successfully exported key")
