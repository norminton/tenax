from __future__ import annotations

import hashlib
import pwd
import re
from pathlib import Path
from typing import Any

from tenax.utils import is_file_safe, path_exists

LD_PRELOAD_PATHS = [
    Path("/etc/ld.so.preload"),
    Path("/etc/ld.so.conf"),
    Path("/etc/ld.so.conf.d"),
    Path.home() / ".bashrc",
    Path.home() / ".profile",
    Path.home() / ".zshrc",
]

TEMP_PATH_PATTERNS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/shm/",
)

USER_PATH_REGEX = re.compile(
    r"(/home/[^/\s]+/|/root/\.|/root/\.local/|/root/\.cache/)",
    re.IGNORECASE,
)

HIDDEN_PATH_REGEX = re.compile(
    r"""
    (
        /tmp/|/var/tmp/|/dev/shm/|/run/shm/|
        /home/[^/\s]+/|/root/
    )
    \.[^/\s'"]+
    """,
    re.IGNORECASE | re.VERBOSE,
)

LD_PRELOAD_REGEX = re.compile(
    r"\bLD_PRELOAD\s*=\s*['\"]?([^'\"\s]+)",
    re.IGNORECASE,
)

LD_LIBRARY_PATH_REGEX = re.compile(
    r"\bLD_LIBRARY_PATH\s*=\s*['\"]?([^'\"\n]+)",
    re.IGNORECASE,
)

SHARED_OBJECT_REGEX = re.compile(
    r"/[^\s'\";|]+\.so(?:\.\d+)*",
    re.IGNORECASE,
)

SUSPICIOUS_SO_NAME_REGEX = re.compile(
    r"""
    (
        \.so\.(bak|old|tmp|test|hidden) |
        lib\w*inject\w*\.so |
        lib\w*hijack\w*\.so |
        lib\w*hook\w*\.so
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def analyze_ld_preload_locations() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in LD_PRELOAD_PATHS:
        if not path_exists(base):
            continue

        if base.is_dir():
            for child in base.iterdir():
                child_str = str(child)
                if child_str in seen_paths:
                    continue
                seen_paths.add(child_str)

                if not is_file_safe(child):
                    continue

                finding = _analyze_artifact(child)
                if finding:
                    findings.append(finding)
        else:
            base_str = str(base)
            if base_str in seen_paths:
                continue
            seen_paths.add(base_str)

            if is_file_safe(base):
                finding = _analyze_artifact(base)
                if finding:
                    findings.append(finding)

    return findings


def collect_ld_preload_locations(hash_files: bool = False) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in LD_PRELOAD_PATHS:
        if not path_exists(base):
            continue

        if base.is_dir():
            for child in base.iterdir():
                child_str = str(child)
                if child_str in seen_paths:
                    continue
                seen_paths.add(child_str)

                if not is_file_safe(child):
                    continue
                artifacts.append(_build_collect_record(child, hash_files))
        else:
            base_str = str(base)
            if base_str in seen_paths:
                continue
            seen_paths.add(base_str)

            if is_file_safe(base):
                artifacts.append(_build_collect_record(base, hash_files))

    return artifacts


def _analyze_artifact(path: Path) -> dict[str, Any] | None:
    if path.is_symlink():
        return _analyze_symlink(path)
    if path.is_file():
        return _analyze_file(path)
    return None


def _analyze_symlink(path: Path) -> dict[str, Any] | None:
    hits: dict[str, dict[str, Any]] = {}

    try:
        target = path.resolve(strict=False)
        target_str = str(target)
    except Exception:
        return None

    if _path_startswith_any(target_str, TEMP_PATH_PATTERNS):
        _record_hit(
            hits,
            reason="LD preload configuration symlink points to a temporary path",
            score=95,
            preview=f"symlink -> {target_str}",
            category="temp-target",
        )

    if USER_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="LD preload configuration symlink points to a user-controlled path",
            score=90,
            preview=f"symlink -> {target_str}",
            category="user-target",
        )

    if HIDDEN_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="LD preload configuration symlink points to a hidden path",
            score=85,
            preview=f"symlink -> {target_str}",
            category="hidden-target",
        )

    return _finalize_finding(path, hits)


def _analyze_file(path: Path) -> dict[str, Any] | None:
    hits: dict[str, dict[str, Any]] = {}

    stat_info = _safe_stat(path)
    if stat_info:
        mode = stat_info.st_mode & 0o777

        if mode & 0o002:
            _record_hit(
                hits,
                reason="LD preload configuration is world-writable",
                score=100,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )

    try:
        content = path.read_text(errors="ignore")
    except Exception:
        return None

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        _detect_ld_preload(hits, stripped, line_number)
        _detect_ld_library_path(hits, stripped, line_number)

    return _finalize_finding(path, hits)

def _detect_ld_preload(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    match = LD_PRELOAD_REGEX.search(line)
    if not match:
        return

    value = match.group(1).strip()
    value_lower = value.lower()

    _analyze_library_path_value(hits, value, value_lower, line, line_number, "LD_PRELOAD")


def _detect_ld_library_path(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    match = LD_LIBRARY_PATH_REGEX.search(line)
    if not match:
        return

    value = match.group(1).strip()

    for part in [p.strip() for p in value.split(":") if p.strip()]:
        _analyze_library_path_value(
            hits,
            part,
            part.lower(),
            line,
            line_number,
            "LD_LIBRARY_PATH",
        )


def _analyze_library_path_value(
    hits: dict[str, dict[str, Any]],
    value: str,
    value_lower: str,
    line: str,
    line_number: int,
    variable_name: str,
) -> None:
    if _path_startswith_any(value_lower, TEMP_PATH_PATTERNS):
        _record_hit(
            hits,
            reason=f"{variable_name} points to a temporary path",
            score=95,
            preview=_with_line_number(line_number, line),
            category="temp-library-path",
        )

    if USER_PATH_REGEX.search(value):
        _record_hit(
            hits,
            reason=f"{variable_name} points to a user-controlled path",
            score=90,
            preview=_with_line_number(line_number, line),
            category="user-library-path",
        )

    if HIDDEN_PATH_REGEX.search(value):
        _record_hit(
            hits,
            reason=f"{variable_name} points to a hidden path",
            score=85,
            preview=_with_line_number(line_number, line),
            category="hidden-library-path",
        )

    if SHARED_OBJECT_REGEX.search(value):
        if SUSPICIOUS_SO_NAME_REGEX.search(value):
            _record_hit(
                hits,
                reason=f"{variable_name} references a suspicious shared object name",
                score=85,
                preview=_with_line_number(line_number, line),
                category="suspicious-so-name",
            )


def _apply_compound_behavior_bonuses(hits: dict[str, dict[str, Any]]) -> None:
    categories = {entry["category"] for entry in hits.values()}

    if "ld-preload" in categories and any(
        category in {"temp-library-path", "user-library-path", "hidden-library-path"}
        for category in categories
    ):
        _record_hit(
            hits,
            reason="LD_PRELOAD is combined with a high-risk library path",
            score=35,
            preview=None,
            category="compound-preload-risk-path",
        )

    if "ld-preload" in categories and "direct-so-reference" in categories:
        _record_hit(
            hits,
            reason="LD_PRELOAD directly references a shared object for forced library injection",
            score=30,
            preview=None,
            category="compound-preload-direct-so",
        )

    if "direct-so-reference" in categories and "suspicious-so-name" in categories:
        _record_hit(
            hits,
            reason="Shared object reference uses a suspicious library naming pattern",
            score=25,
            preview=None,
            category="compound-suspicious-so",
        )


def _finalize_finding(path: Path, hits: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    if not hits:
        return None

    categories = {entry["category"] for entry in hits.values()}
    score = sum(int(entry["score"]) for entry in hits.values())

    if not any(cat in categories for cat in {
        "temp-library-path",
        "user-library-path",
        "hidden-library-path",
        "suspicious-so-name",
    }):
        return None

    primary_reason = max(
        hits.values(),
        key=lambda entry: int(entry["score"]),
    )["reason"]

    preview = next((entry["preview"] for entry in hits.values() if entry.get("preview")), None)

    return {
        "path": str(path),
        "score": score,
        "severity": _severity(score),
        "reason": primary_reason,
        "reasons": [entry["reason"] for entry in hits.values()],
        "preview": preview,
    }

def _record_hit(
    hits: dict[str, dict[str, Any]],
    reason: str,
    score: int,
    preview: str | None,
    category: str,
) -> None:
    existing = hits.get(category)
    if existing is None or score > int(existing["score"]):
        hits[category] = {
            "reason": reason,
            "score": int(score),
            "preview": preview,
            "category": category,
        }


def _build_collect_record(path: Path, hash_files: bool = False) -> dict[str, Any]:
    record = {
        "path": str(path),
        "type": "artifact",
        "exists": path.exists(),
        "owner": "unknown",
        "permissions": "unknown",
    }

    try:
        stat_info = path.lstat() if path.is_symlink() else path.stat()
        record["permissions"] = oct(stat_info.st_mode & 0o777)
    except Exception:
        pass

    try:
        stat_info = path.lstat() if path.is_symlink() else path.stat()
        record["owner"] = pwd.getpwuid(stat_info.st_uid).pw_name
    except Exception:
        pass

    if hash_files and path.exists() and path.is_file() and not path.is_symlink():
        try:
            record["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        except Exception:
            pass

    return record


def _safe_stat(path: Path):
    try:
        return path.stat()
    except Exception:
        return None


def _owner_from_uid(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def _path_startswith_any(path_value: str, prefixes: tuple[str, ...]) -> bool:
    path_lower = path_value.lower()
    return any(path_lower.startswith(prefix.lower()) for prefix in prefixes)


def _with_line_number(line_number: int, line: str) -> str:
    return f"line {line_number}: {line.strip()}"


def _severity(score: int) -> str:
    if score >= 140:
        return "CRITICAL"
    if score >= 90:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"