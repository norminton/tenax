import hashlib
import os
import pwd
import stat
from pathlib import Path


def sha256_file(path: Path) -> str | None:
    try:
        hasher = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, FileNotFoundError, IsADirectoryError, OSError):
        return None


def get_file_owner(path: Path) -> str:
    try:
        return pwd.getpwuid(path.stat().st_uid).pw_name
    except Exception:
        return "unknown"


def get_file_permissions(path: Path) -> str:
    try:
        return stat.filemode(path.stat().st_mode)
    except Exception:
        return "unknown"


def path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except Exception:
        return False
