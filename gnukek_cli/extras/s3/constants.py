# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/customizations/s3.html#boto3.s3.transfer.TransferConfig
ENCRYPTION_CHUNK_LENGTH = 8 * 1024 * 1024  # 8 MB

DOWNLOAD_BUFFER_TIMEOUT_SEC = 10

DOWNLOAD_MEMORY_LIMIT_BYTES = 512 * 1024 * 1024  # 512 MB
