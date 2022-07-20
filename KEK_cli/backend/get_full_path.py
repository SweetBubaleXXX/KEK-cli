from os import getcwd, path
from typing import Optional


def get_full_path(file: str, work_dir: Optional[str] = None) -> str:
    if not work_dir:
        work_dir = getcwd()
    return path.abspath(path.join(work_dir, file))
