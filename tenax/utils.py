import grp
import hashlib
import pwd
import stat
from pathlib import Path


def safe_stat(path: Path, *, follow_symlinks: bool = True):
    try:
        return path.stat() if follow_symlinks else path.lstat()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def sha256_file(path: Path, *, max_bytes: int | None = None) -> str | None:
    try:
        stat_info = safe_stat(path)
        if stat_info is None:
            return None
        if max_bytes is not None and stat_info.st_size > max_bytes:
            return None
        hasher = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, FileNotFoundError, IsADirectoryError, OSError):
        return None


def get_file_owner(path: Path) -> str:
    try:
        stat_info = safe_stat(path, follow_symlinks=not path.is_symlink())
        if stat_info is None:
            return "unknown"
        return pwd.getpwuid(stat_info.st_uid).pw_name
    except Exception:
        return "unknown"


def get_file_group(path: Path) -> str:
    try:
        stat_info = safe_stat(path, follow_symlinks=not path.is_symlink())
        if stat_info is None:
            return "unknown"
        return grp.getgrgid(stat_info.st_gid).gr_name
    except Exception:
        return "unknown"


def get_file_permissions(path: Path) -> str:
    try:
        stat_info = safe_stat(path, follow_symlinks=not path.is_symlink())
        if stat_info is None:
            return "unknown"
        return stat.filemode(stat_info.st_mode)
    except Exception:
        return "unknown"


def path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except Exception:
        return False


def is_file_safe(path: Path) -> bool:
    try:
        return path.is_file()
    except Exception:
        return False


def build_collect_record(path: Path, hash_files: bool = False) -> dict[str, object]:
    record: dict[str, object] = {
        "path": str(path),
        "type": "artifact",
        "exists": path_exists(path),
        "owner": get_file_owner(path),
        "group": get_file_group(path),
        "permissions": "unknown",
    }

    stat_info = safe_stat(path, follow_symlinks=not path.is_symlink())
    if stat_info is not None:
        record["permissions"] = oct(stat_info.st_mode & 0o777)

    if hash_files and path_exists(path) and is_file_safe(path) and not path.is_symlink():
        sha256 = sha256_file(path)
        if sha256:
            record["sha256"] = sha256

    return record
