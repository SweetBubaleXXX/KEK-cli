import functools
import os
from io import BytesIO

import boto3
import pytest
from moto import mock_aws

from gnukek_cli.extras.s3.command_handlers.download import (
    DownloadContext,
    DownloadHandler,
)
from gnukek_cli.extras.s3.command_handlers.upload import UploadContext, UploadHandler
from tests.constants import SAMPLE_MESSAGE

BUCKET_NAME = "test-bucket"
OBJECT_NAME = "test-object"


@pytest.fixture(scope="module")
def aws_credentials():
    os.environ["AWS_CONFIG_FILE"] = ""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def s3_client():
    with mock_aws():
        conn = boto3.resource("s3")
        conn.create_bucket(Bucket=BUCKET_NAME)

        yield boto3.client("s3")


@pytest.fixture
def saved_encrypted_file(s3_client, encrypted_message):
    encrypted_buffer = BytesIO(encrypted_message)
    s3_client.upload_fileobj(encrypted_buffer, BUCKET_NAME, OBJECT_NAME)


@pytest.fixture
def create_upload_handler(key_provider):
    return functools.partial(UploadHandler, key_provider=key_provider)


@pytest.fixture
def create_download_handler(key_provider):
    return functools.partial(DownloadHandler, key_provider=key_provider)


@pytest.mark.usefixtures("aws_credentials", "saved_public_key", "settings_file")
@pytest.mark.parametrize("no_chunk", [False, True])
def test_upload(
    create_upload_handler, output_buffer, s3_client, sample_key_pair, no_chunk
):
    handle = create_upload_handler(
        UploadContext(
            input_file=BytesIO(SAMPLE_MESSAGE),
            bucket_name=BUCKET_NAME,
            object_name=OBJECT_NAME,
            no_chunk=no_chunk,
        )
    )
    handle()

    s3_client.download_fileobj(BUCKET_NAME, OBJECT_NAME, output_buffer)

    encrypted_content = output_buffer.getvalue()
    decrypted_content = sample_key_pair.decrypt(encrypted_content)

    assert decrypted_content == SAMPLE_MESSAGE


@pytest.mark.usefixtures(
    "aws_credentials", "saved_encrypted_file", "saved_private_key", "settings_file"
)
def test_download(create_download_handler, output_buffer):
    handle = create_download_handler(
        DownloadContext(
            bucket_name=BUCKET_NAME,
            object_name=OBJECT_NAME,
            output_file=output_buffer,
        )
    )
    handle()

    downloaded_content = output_buffer.getvalue()

    assert downloaded_content == SAMPLE_MESSAGE
