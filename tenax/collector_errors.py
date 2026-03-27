from __future__ import annotations

import errno
from pathlib import Path
from typing import Any


ERROR_TYPES = {
    "permission_denied",
    "missing_path",
    "unsupported_dependency",
    "parse_failure",
    "module_failure",
}


def build_error(
    *,
    error_type: str,
    message: str,
    module: str | None = None,
    path: str | None = None,
    context: dict[str, Any] | None = None,
    exception: Exception | None = None,
) -> dict[str, Any]:
    normalized_type = error_type if error_type in ERROR_TYPES else "module_failure"
    error: dict[str, Any] = {
        "type": normalized_type,
        "message": message,
    }
    if module is not None:
        error["module"] = module
    if path is not None:
        error["path"] = path
    if context:
        error["context"] = context
    if exception is not None:
        error["detail"] = f"{type(exception).__name__}: {exception}"
    return error


def categorize_exception(exc: Exception) -> str:
    if isinstance(exc, PermissionError):
        return "permission_denied"
    if isinstance(exc, FileNotFoundError):
        return "missing_path"

    os_error = exc if isinstance(exc, OSError) else None
    if os_error is not None:
        if os_error.errno == errno.EACCES:
            return "permission_denied"
        if os_error.errno == errno.ENOENT:
            return "missing_path"

    return "module_failure"


def categorize_missing_tool(tool_name: str) -> dict[str, Any]:
    return build_error(
        error_type="unsupported_dependency",
        message=f"Required dependency '{tool_name}' is not available.",
        context={"dependency": tool_name},
    )


def infer_path_error_type(path: str | Path | None) -> str:
    if path is None:
        return "module_failure"
    candidate = Path(path)
    if not candidate.exists():
        return "missing_path"
    return "permission_denied"
