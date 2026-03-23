from __future__ import annotations

import hashlib
import pwd
import re
from pathlib import Path
from typing import Any

from tenax.utils import is_file_safe, path_exists

TMP_PATHS = [
    Path("/tmp"),
    Path("/var/tmp"),
    Path("/dev/shm"),
    Path("/run/shm"),
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

HIDDEN_NAME_REGEX = re.compile(
    r"/\.[^/\s]+$",
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

URL_REGEX = re.compile(r"\b(https?|ftp|tftp)://[^\s'\"<>]+", re.IGNORECASE)

DOWNLOAD_TOOL_REGEX = re.compile(
    r"\b(curl|wget|fetch|ftpget|tftp|lwp-download|busybox\s+wget)\b",
    re.IGNORECASE,
)

PIPE_TO_INTERPRETER_REGEX = re.compile(
    r"""
    \b(curl|wget|fetch|ftpget|tftp|lwp-download|busybox\s+wget)\b
    .*?
    (\||;\s*)
    .*?
    \b(sh|bash|dash|ash|ksh|zsh|python|python2|python3|perl|ruby|php)\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

INTERPRETER_ONE_LINER_REGEX = re.compile(
    r"""
    \b(
        python|python2|python3|
        perl|ruby|php|
        awk|lua
    )\b
    .*?
    \s(-c|-e|-r)\s
    """,
    re.IGNORECASE | re.VERBOSE,
)

SOCKET_IMPLANT_REGEXES = [
    re.compile(r"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+", re.IGNORECASE),
    re.compile(r"\bnc(?:at)?\b.*\s-e\s", re.IGNORECASE),
    re.compile(r"\bsocat\b.*\b(exec|system):", re.IGNORECASE),
    re.compile(r"\bmkfifo\b.*\b(?:nc|ncat|netcat)\b", re.IGNORECASE),
    re.compile(r"\bpython(?:2|3)?\b.*\bsocket\b.*\bconnect\s*\(", re.IGNORECASE),
    re.compile(r"\bperl\b.*\bsocket\b.*\bconnect\b", re.IGNORECASE),
    re.compile(r"\bphp\b.*\bfsockopen\s*\(", re.IGNORECASE),
    re.compile(r"\bruby\b.*\bTCPSocket\b", re.IGNORECASE),
]

ENCODED_EXEC_REGEXES = [
    re.compile(r"\bbase64\b.*(-d|--decode)", re.IGNORECASE),
    re.compile(r"\bopenssl\b.*\b(enc|aes)\b.*(-d|--decrypt)", re.IGNORECASE),
    re.compile(r"\bxxd\b.*-r", re.IGNORECASE),
]

ENCODED_TO_EXEC_REGEX = re.compile(
    r"""
    (
        \bbase64\b.*(-d|--decode) |
        \bopenssl\b.*\b(enc|aes)\b.*(-d|--decrypt) |
        \bxxd\b.*-r
    )
    .*?
    (\||;\s*)
    .*?
    \b(sh|bash|dash|ash|python|python2|python3|perl|ruby|php)\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

STEALTH_PERSISTENCE_REGEXES = [
    re.compile(r"\bchmod\b\s+[ugoa]*\+s\b", re.IGNORECASE),
    re.compile(r"\bchmod\b\s+[0-7]*[4567][0-7]{2}\b", re.IGNORECASE),
    re.compile(r"\bsetcap\b", re.IGNORECASE),
    re.compile(r"\bchattr\b\s+\+i\b", re.IGNORECASE),
]

LD_HIJACK_REGEX = re.compile(
    r"\b(LD_PRELOAD|LD_LIBRARY_PATH)\s*=\s*['\"]?([^'\"\s]+)",
    re.IGNORECASE,
)

PATH_HIJACK_REGEX = re.compile(
    r"\bPATH\s*=\s*['\"]?([^'\"\n]+)",
    re.IGNORECASE,
)

DIRECT_EXEC_REGEX = re.compile(
    r"""
    \b(
        sh|bash|dash|ash|ksh|zsh|
        python|python2|python3|perl|ruby|php|
        env|exec|source|\.
    )\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

SUSPICIOUS_FILE_EXT_REGEX = re.compile(
    r"\.(sh|py|pl|rb|php|elf|bin|out|so)$",
    re.IGNORECASE,
)

ELF_MAGIC = b"\x7fELF"


def analyze_tmp_paths() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in TMP_PATHS:
        if not path_exists(base):
            continue

        if base.is_dir():
            for child in _safe_walk(base):
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


def collect_tmp_paths(hash_files: bool = False) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in TMP_PATHS:
        if not path_exists(base):
            continue

        if base.is_dir():
            for child in _safe_walk(base):
                child_str = str(child)
                if child_str in seen_paths:
                    continue
                seen_paths.add(child_str)

                if not is_file_safe(child):
                    continue
                artifacts.append(_build_collect_record(child, hash_files=hash_files))
        else:
            base_str = str(base)
            if base_str in seen_paths:
                continue
            seen_paths.add(base_str)

            if is_file_safe(base):
                artifacts.append(_build_collect_record(base, hash_files=hash_files))

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

    _record_hit(
        hits,
        reason="Artifact in a temporary path is a symlink",
        score=35,
        preview=f"symlink -> {target_str}",
        category="symlink",
    )

    if _path_startswith_any(target_str, TEMP_PATH_PATTERNS):
        _record_hit(
            hits,
            reason="Temporary-path symlink points to another temporary path",
            score=50,
            preview=f"symlink -> {target_str}",
            category="temp-target",
        )

    if USER_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="Temporary-path symlink points to a user-controlled path",
            score=65,
            preview=f"symlink -> {target_str}",
            category="user-target",
        )

    if HIDDEN_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="Temporary-path symlink points to a hidden path",
            score=70,
            preview=f"symlink -> {target_str}",
            category="hidden-target",
        )

    stat_info = _safe_lstat(path)
    if stat_info and stat_info.st_uid != 0:
        _record_hit(
            hits,
            reason="Temporary-path symlink is owned by a non-root account",
            score=30,
            preview=f"owner={_owner_from_uid(stat_info.st_uid)}",
            category="ownership",
        )

    return _finalize_finding(path, hits)


def _analyze_file(path: Path) -> dict[str, Any] | None:
    hits: dict[str, dict[str, Any]] = {}
    path_str = str(path)
    path_lower = path_str.lower()

    _record_hit(
        hits,
        reason="Artifact resides in a temporary execution path",
        score=20,
        preview=path_str,
        category="temp-resident",
    )

    if HIDDEN_NAME_REGEX.search(path_str):
        _record_hit(
            hits,
            reason="Temporary-path artifact uses a hidden filename",
            score=55,
            preview=path_str,
            category="hidden-name",
        )

    stat_info = _safe_stat(path)
    if stat_info:
        mode = stat_info.st_mode & 0o777

        if stat_info.st_uid != 0:
            _record_hit(
                hits,
                reason="Temporary-path artifact is owned by a non-root account",
                score=25,
                preview=f"owner={_owner_from_uid(stat_info.st_uid)}",
                category="ownership",
            )

        if mode & 0o111:
            _record_hit(
                hits,
                reason="Temporary-path artifact is directly executable",
                score=45,
                preview=f"mode={oct(mode)}",
                category="executable-bit",
            )

        if mode & 0o002:
            _record_hit(
                hits,
                reason="Temporary-path artifact is world-writable",
                score=65,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )
        elif mode & 0o020:
            _record_hit(
                hits,
                reason="Temporary-path artifact is group-writable",
                score=35,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )

    try:
        raw = path.read_bytes()
    except Exception:
        return _finalize_finding(path, hits)

    if raw[:4] == ELF_MAGIC:
        _record_hit(
            hits,
            reason="Temporary-path artifact is an ELF binary",
            score=85,
            preview=path_str,
            category="elf-binary",
        )

    if b"\x00" in raw[:4096] and raw[:4] != ELF_MAGIC:
        _record_hit(
            hits,
            reason="Temporary-path artifact contains binary content",
            score=55,
            preview="[binary content omitted]",
            category="binary",
        )
        return _finalize_finding(path, hits)

    try:
        content = raw.decode("utf-8", errors="ignore")
    except Exception:
        return _finalize_finding(path, hits)

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue

        line_lower = stripped.lower()

        if stripped.startswith("#"):
            continue

        _detect_download_behavior(hits, stripped, line_lower, line_number)
        _detect_pipe_to_interpreter(hits, stripped, line_number)
        _detect_interpreter_one_liners(hits, stripped, line_lower, line_number)
        _detect_reverse_shells(hits, stripped, line_number)
        _detect_encoded_execution(hits, stripped, line_number)
        _detect_temp_or_user_exec(hits, stripped, line_lower, line_number)
        _detect_ld_hijack(hits, stripped, line_number)
        _detect_path_hijack(hits, stripped, line_number)
        _detect_stealth_or_privilege_changes(hits, stripped, line_lower, line_number)

    _apply_compound_behavior_bonuses(hits)

    return _finalize_finding(path, hits)

def _detect_download_behavior(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    has_download_tool = bool(DOWNLOAD_TOOL_REGEX.search(line))
    has_url = bool(URL_REGEX.search(line))

    if has_download_tool and has_url:
        _record_hit(
            hits,
            reason="Temporary-path artifact downloads content from a remote URL",
            score=60,
            preview=_with_line_number(line_number, line),
            category="download",
        )

    if has_download_tool and any(token in line_lower for token in ("-o ", "--output", "> /", ">> /")):
        if _contains_high_risk_path(line_lower):
            _record_hit(
                hits,
                reason="Temporary-path artifact downloads remote content into a high-risk path",
                score=70,
                preview=_with_line_number(line_number, line),
                category="download-to-risk-path",
            )


def _detect_pipe_to_interpreter(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    if PIPE_TO_INTERPRETER_REGEX.search(line):
        _record_hit(
            hits,
            reason="Temporary-path artifact downloads and executes payload inline",
            score=100,
            preview=_with_line_number(line_number, line),
            category="download-exec",
        )


def _detect_interpreter_one_liners(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    if INTERPRETER_ONE_LINER_REGEX.search(line):
        high_signal_terms = (
            "socket",
            "subprocess",
            "pty",
            "eval(",
            "exec(",
            "__import__",
            "os.system",
            "base64",
            "marshal",
            "pickle",
            "urllib",
            "requests",
            "connect(",
        )
        if any(term in line_lower for term in high_signal_terms):
            _record_hit(
                hits,
                reason="Temporary-path artifact contains a high-risk interpreter one-liner",
                score=70,
                preview=_with_line_number(line_number, line),
                category="one-liner",
            )


def _detect_reverse_shells(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    for regex in SOCKET_IMPLANT_REGEXES:
        if regex.search(line):
            _record_hit(
                hits,
                reason="Temporary-path artifact contains reverse-shell or socket-based execution behavior",
                score=100,
                preview=_with_line_number(line_number, line),
                category="reverse-shell",
            )
            break

def _detect_encoded_execution(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    if ENCODED_TO_EXEC_REGEX.search(line):
        _record_hit(
            hits,
            reason="Temporary-path artifact decodes content and immediately executes it",
            score=95,
            preview=_with_line_number(line_number, line),
            category="decode-exec",
        )
        return

    for regex in ENCODED_EXEC_REGEXES:
        if regex.search(line):
            _record_hit(
                hits,
                reason="Temporary-path artifact contains encoded payload handling logic",
                score=45,
                preview=_with_line_number(line_number, line),
                category="encoded",
            )
            break


def _detect_temp_or_user_exec(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    if not DIRECT_EXEC_REGEX.search(line):
        return

    _record_hit(
        hits,
        reason="Temporary-path artifact performs direct execution behavior",
        score=35,
        preview=_with_line_number(line_number, line),
        category="direct-exec",
    )

    if _path_startswith_any(line_lower, TEMP_PATH_PATTERNS):
        _record_hit(
            hits,
            reason="Temporary-path artifact executes another temporary-path payload",
            score=85,
            preview=_with_line_number(line_number, line),
            category="temp-exec",
        )
        return

    if USER_PATH_REGEX.search(line):
        _record_hit(
            hits,
            reason="Temporary-path artifact executes content from a user-controlled path",
            score=75,
            preview=_with_line_number(line_number, line),
            category="user-exec",
        )
        return

    if HIDDEN_PATH_REGEX.search(line):
        _record_hit(
            hits,
            reason="Temporary-path artifact executes content from a hidden path",
            score=80,
            preview=_with_line_number(line_number, line),
            category="hidden-exec",
        )
        return

    path_matches = re.findall(r"(/[^\s'\";|,]+)", line)
    for matched_path in path_matches:
        matched_lower = matched_path.lower()

        if SUSPICIOUS_FILE_EXT_REGEX.search(matched_path):
            if _path_startswith_any(matched_lower, TEMP_PATH_PATTERNS):
                _record_hit(
                    hits,
                    reason="Temporary-path artifact references another executable script or binary in a temporary path",
                    score=80,
                    preview=_with_line_number(line_number, line),
                    category="temp-exec",
                )
                return

            if USER_PATH_REGEX.search(matched_path):
                _record_hit(
                    hits,
                    reason="Temporary-path artifact references an executable script or binary in a user-controlled path",
                    score=75,
                    preview=_with_line_number(line_number, line),
                    category="user-exec",
                )
                return

            if HIDDEN_PATH_REGEX.search(matched_path):
                _record_hit(
                    hits,
                    reason="Temporary-path artifact references an executable script or binary in a hidden path",
                    score=80,
                    preview=_with_line_number(line_number, line),
                    category="hidden-exec",
                )
                return


def _detect_ld_hijack(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    match = LD_HIJACK_REGEX.search(line)
    if not match:
        return

    variable_name = match.group(1)
    variable_value = match.group(2)

    _record_hit(
        hits,
        reason=f"Temporary-path artifact sets {variable_name}",
        score=60,
        preview=_with_line_number(line_number, line),
        category="ld-hijack",
    )

    if _path_startswith_any(variable_value.lower(), TEMP_PATH_PATTERNS):
        _record_hit(
            hits,
            reason=f"Temporary-path artifact sets {variable_name} to a temporary path",
            score=95,
            preview=_with_line_number(line_number, line),
            category="ld-hijack-risk",
        )
        return

    if USER_PATH_REGEX.search(variable_value):
        _record_hit(
            hits,
            reason=f"Temporary-path artifact sets {variable_name} to a user-controlled path",
            score=90,
            preview=_with_line_number(line_number, line),
            category="ld-hijack-risk",
        )
        return

    if HIDDEN_PATH_REGEX.search(variable_value):
        _record_hit(
            hits,
            reason=f"Temporary-path artifact sets {variable_name} to a hidden path",
            score=85,
            preview=_with_line_number(line_number, line),
            category="ld-hijack-risk",
        )


def _detect_path_hijack(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    match = PATH_HIJACK_REGEX.search(line)
    if not match:
        return

    path_value = match.group(1).strip()
    path_parts = [part.strip() for part in path_value.split(":") if part.strip()]

    _record_hit(
        hits,
        reason="Temporary-path artifact modifies PATH",
        score=35,
        preview=_with_line_number(line_number, line),
        category="path-hijack",
    )

    for part in path_parts:
        part_lower = part.lower()

        if _path_startswith_any(part_lower, TEMP_PATH_PATTERNS):
            _record_hit(
                hits,
                reason="Temporary-path artifact modifies PATH to include a temporary directory",
                score=85,
                preview=_with_line_number(line_number, line),
                category="path-hijack-risk",
            )
            return

        if USER_PATH_REGEX.search(part):
            _record_hit(
                hits,
                reason="Temporary-path artifact modifies PATH to include a user-controlled directory",
                score=80,
                preview=_with_line_number(line_number, line),
                category="path-hijack-risk",
            )
            return

        if HIDDEN_PATH_REGEX.search(part):
            _record_hit(
                hits,
                reason="Temporary-path artifact modifies PATH to include a hidden directory",
                score=75,
                preview=_with_line_number(line_number, line),
                category="path-hijack-risk",
            )
            return


def _detect_stealth_or_privilege_changes(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    for regex in STEALTH_PERSISTENCE_REGEXES:
        if regex.search(line):
            if "chmod 755" in line_lower or "chmod 755 " in line_lower:
                return
            if "chmod 644" in line_lower or "chmod 644 " in line_lower:
                return
            if "chmod 600" in line_lower or "chmod 600 " in line_lower:
                return
            if "chown root:root" in line_lower:
                return

            _record_hit(
                hits,
                reason="Temporary-path artifact contains stealth or privilege-manipulation logic",
                score=85,
                preview=_with_line_number(line_number, line),
                category="stealth-privilege",
            )
            return

def _apply_compound_behavior_bonuses(hits: dict[str, dict[str, Any]]) -> None:
    categories = {entry["category"] for entry in hits.values()}

    if any("download" in category for category in categories) and any(
        category in {
            "download-exec",
            "reverse-shell",
            "one-liner",
            "decode-exec",
            "temp-exec",
            "user-exec",
            "hidden-exec",
        }
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Temporary-path artifact combines download behavior with active execution logic",
            score=35,
            preview=None,
            category="compound-download-exec",
        )

    if "elf-binary" in categories and any(
        category in {
            "executable-bit",
            "hidden-name",
            "download-exec",
            "reverse-shell",
            "ld-hijack-risk",
            "path-hijack-risk",
        }
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Temporary-path ELF binary is paired with additional high-risk execution indicators",
            score=30,
            preview=None,
            category="compound-elf-risk",
        )

    if "path-hijack" in categories and any(
        category in {
            "path-hijack-risk",
            "temp-exec",
            "user-exec",
            "hidden-exec",
            "ld-hijack",
            "ld-hijack-risk",
        }
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Temporary-path artifact combines PATH hijacking with suspicious execution behavior",
            score=25,
            preview=None,
            category="compound-path-hijack",
        )

    if "ld-hijack" in categories and any(
        category in {
            "ld-hijack-risk",
            "temp-exec",
            "user-exec",
            "hidden-exec",
        }
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Temporary-path artifact combines LD preload behavior with suspicious execution indicators",
            score=25,
            preview=None,
            category="compound-ld-hijack",
        )

    if "symlink" in categories and any(
        category in {"temp-target", "user-target", "hidden-target"}
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Temporary-path symlink redirects execution into a high-risk target location",
            score=20,
            preview=None,
            category="compound-symlink-risk",
        )


def _finalize_finding(path: Path, hits: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    if not hits:
        return None

    reasons = [entry["reason"] for entry in hits.values()]
    previews = [entry["preview"] for entry in hits.values() if entry.get("preview")]
    categories = {entry["category"] for entry in hits.values()}
    score = sum(int(entry["score"]) for entry in hits.values())

    high_confidence_categories = {
        "temp-target",
        "user-target",
        "hidden-target",
        "temp-resident",
        "hidden-name",
        "ownership",
        "permissions",
        "executable-bit",
        "elf-binary",
        "binary",
        "download-exec",
        "reverse-shell",
        "decode-exec",
        "temp-exec",
        "user-exec",
        "hidden-exec",
        "ld-hijack-risk",
        "path-hijack-risk",
        "stealth-privilege",
        "compound-download-exec",
        "compound-elf-risk",
        "compound-path-hijack",
        "compound-ld-hijack",
        "compound-symlink-risk",
    }

    low_signal_only_categories = {
        "download",
        "download-to-risk-path",
        "encoded",
        "one-liner",
        "direct-exec",
        "ld-hijack",
        "path-hijack",
        "symlink",
    }

    has_high_confidence = bool(categories & high_confidence_categories)
    only_low_signal = categories and categories.issubset(low_signal_only_categories)

    if only_low_signal and score < 90:
        return None

    if not has_high_confidence and score < 95 and len(categories) < 2:
        return None

    primary_reason = max(
        hits.values(),
        key=lambda entry: int(entry["score"]),
    )["reason"]

    preview = previews[0] if previews else None

    return {
        "path": str(path),
        "score": score,
        "severity": _severity(score),
        "reason": primary_reason,
        "reasons": reasons,
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


def _safe_walk(base: Path) -> list[Path]:
    output: list[Path] = []
    try:
        for child in base.rglob("*"):
            if child.is_file() or child.is_symlink():
                output.append(child)
    except Exception:
        return output
    return output


def _safe_stat(path: Path):
    try:
        return path.stat()
    except Exception:
        return None


def _safe_lstat(path: Path):
    try:
        return path.lstat()
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


def _contains_high_risk_path(line_lower: str) -> bool:
    if any(token in line_lower for token in TEMP_PATH_PATTERNS):
        return True
    return bool(USER_PATH_REGEX.search(line_lower))


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