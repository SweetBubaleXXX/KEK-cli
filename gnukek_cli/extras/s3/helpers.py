import re


def parse_s3_object_location(file_location: str) -> tuple[str, str]:
    if not re.match(r"^[^/]+/.+$", file_location):
        raise ValueError()
    bucket_name, object_name = file_location.split("/", 1)
    return (bucket_name, object_name)
