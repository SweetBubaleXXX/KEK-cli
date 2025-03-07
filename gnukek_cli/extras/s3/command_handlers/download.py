from dataclasses import dataclass
from typing import BinaryIO

import boto3
from dependency_injector.wiring import Provide, inject

from gnukek_cli.container import Container
from gnukek_cli.keys.provider import KeyProvider


@dataclass
class DownloadContext:
    bucket_name: str
    object_name: str
    output_file: BinaryIO


class DownloadHandler:
    @inject
    def __init__(
        self,
        context: DownloadContext,
        *,
        key_provider: KeyProvider = Provide[Container.key_provider],
    ) -> None:
        self.context = context
        self._key_provider = key_provider

    def __call__(self) -> None:
        s3_client = boto3.client("s3")
