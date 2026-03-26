from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from tenax.checks.common import (
    build_collect_record as shared_build_collect_record,
    contains_high_risk_path as shared_contains_high_risk_path,
    finalize_finding as shared_finalize_finding,
    owner_from_uid as shared_owner_from_uid,
    path_startswith_any as shared_path_startswith_any,
    record_hit as shared_record_hit,
    safe_lstat as shared_safe_lstat,
    safe_stat as shared_safe_stat,
    safe_walk as shared_safe_walk,
    severity_from_score,
    with_line_number as shared_with_line_number,
)
from tenax.utils import is_file_safe, path_exists

CRON_PATHS = [
    Path("/etc/crontab"),
    Path("/etc/cron.d"),
    Path("/etc/cron.daily"),
    Path("/etc/cron.hourly"),
    Path("/etc/cron.weekly"),
    Path("/etc/cron.monthly"),
    Path("/var/spool/cron"),
    Path("/var/spool/cron/crontabs"),
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
    r"^\s*PATH\s*=\s*['\"]?([^'\"\n]+)",
    re.IGNORECASE,
)

MAILTO_REGEX = re.compile(r"^\s*MAILTO\s*=\s*(.+)", re.IGNORECASE)
SHELL_REGEX = re.compile(r"^\s*SHELL\s*=\s*(.+)", re.IGNORECASE)

PROCESS_DETACH_REGEXES = [
    re.compile(r"\bnohup\b", re.IGNORECASE),
    re.compile(r"\bsetsid\b", re.IGNORECASE),
    re.compile(r"\bdisown\b", re.IGNORECASE),
]

DIRECT_EXEC_REGEX = re.compile(
    r"""
    \b(
        sh|bash|dash|ash|ksh|zsh|
        python|python2|python3|perl|ruby|php|
        su|runuser|sudo|
        exec
    )\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

SUSPICIOUS_FILE_EXT_REGEX = re.compile(
    r"\.(sh|py|pl|rb|php|elf|bin|out)$",
    re.IGNORECASE,
)

AT_REBOOT_REGEX = re.compile(r"^\s*@reboot\b", re.IGNORECASE)
FREQUENT_SCHEDULE_REGEXES = [
    re.compile(r"^\s*\*\s+\*\s+\*\s+\*\s+\*", re.IGNORECASE),
    re.compile(r"^\s*\*/[1-5]\s+\*\s+\*\s+\*\s+\*", re.IGNORECASE),
    re.compile(r"^\s*\d+(,\d+)+\s+\*\s+\*\s+\*\s+\*", re.IGNORECASE),
]

CRON_JOB_REGEX = re.compile(
    r"""
    ^
    \s*
    (
        @\w+ |
        \S+\s+\S+\s+\S+\s+\S+\s+\S+(?:\s+\S+)?
    )
    \s+
    (?P<command>.+)
    $
    """,
    re.IGNORECASE | re.VERBOSE,
)

COMMENT_REGEX = re.compile(r"^\s*#")

CRON_METADATA_PREFIXES = (
    "mailto=",
    "shell=",
    "path=",
    "home=",
)


def analyze_cron_locations() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in CRON_PATHS:
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


def collect_cron_locations(hash_files: bool = False) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in CRON_PATHS:
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

    if _path_startswith_any(target_str, TEMP_PATH_PATTERNS):
        _record_hit(
            hits,
            reason="Cron symlink target points into a temporary execution path",
            score=95,
            preview=f"symlink -> {target_str}",
            category="temp-target",
        )

    if USER_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="Cron symlink target points into a user-controlled path",
            score=90,
            preview=f"symlink -> {target_str}",
            category="user-target",
        )

    if HIDDEN_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="Cron symlink target references a hidden path",
            score=80,
            preview=f"symlink -> {target_str}",
            category="hidden-target",
        )

    stat_info = _safe_lstat(path)
    if stat_info and stat_info.st_uid != 0:
        owner_name = _owner_from_uid(stat_info.st_uid)
        _record_hit(
            hits,
            reason="Cron symlink is owned by a non-root account",
            score=75,
            preview=f"owner={owner_name}",
            category="ownership",
        )

    return _finalize_finding(path, hits)


def _analyze_file(path: Path) -> dict[str, Any] | None:
    hits: dict[str, dict[str, Any]] = {}

    stat_info = _safe_stat(path)
    if stat_info:
        mode = stat_info.st_mode & 0o777
        owner_name = _owner_from_uid(stat_info.st_uid)

        if stat_info.st_uid != 0:
            _record_hit(
                hits,
                reason="Cron file is owned by a non-root account",
                score=70,
                preview=f"owner={owner_name}",
                category="ownership",
            )

        if mode & 0o002:
            _record_hit(
                hits,
                reason="Cron file is world-writable",
                score=100,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )
        elif mode & 0o020:
            _record_hit(
                hits,
                reason="Cron file is group-writable",
                score=60,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )

    try:
        raw = path.read_bytes()
    except Exception:
        return _finalize_finding(path, hits)

    if b"\x00" in raw[:4096]:
        _record_hit(
            hits,
            reason="Cron artifact contains binary content instead of expected text job data",
            score=85,
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

        if COMMENT_REGEX.match(stripped):
            continue

        line_lower = stripped.lower()

        _detect_schedule_risk(hits, stripped, line_number)
        _detect_mailto_abuse(hits, stripped, line_number)
        _detect_shell_abuse(hits, stripped, line_number)
        _detect_path_hijack(hits, stripped, line_number)

        command = _extract_cron_command(stripped)
        if not command:
            continue

        command_lower = command.lower()

        _detect_download_behavior(hits, command, command_lower, line_number)
        _detect_pipe_to_interpreter(hits, command, line_number)
        _detect_interpreter_one_liners(hits, command, command_lower, line_number)
        _detect_reverse_shells(hits, command, line_number)
        _detect_encoded_execution(hits, command, line_number)
        _detect_temp_or_user_exec(hits, command, command_lower, line_number)
        _detect_ld_hijack(hits, command, line_number)
        _detect_stealth_or_privilege_changes(hits, command, command_lower, line_number)
        _detect_process_detach(hits, command, line_number)
        _detect_suspicious_direct_exec(hits, command, command_lower, line_number)

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
            reason="Cron artifact downloads content from a remote URL",
            score=55,
            preview=_with_line_number(line_number, line),
            category="download",
        )

    if has_download_tool and any(token in line_lower for token in ("-o ", "--output", "> /", ">> /")):
        if _contains_high_risk_path(line_lower):
            _record_hit(
                hits,
                reason="Cron artifact downloads remote content into a high-risk local path",
                score=70,
                preview=_with_line_number(line_number, line),
                category="download-to-risk-path",
            )


def _detect_schedule_risk(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    if AT_REBOOT_REGEX.search(line):
        _record_hit(
            hits,
            reason="Cron persistence is configured to run at reboot",
            score=55,
            preview=_with_line_number(line_number, line),
            category="suspicious-schedule",
        )
        return

    for regex in FREQUENT_SCHEDULE_REGEXES:
        if regex.search(line):
            _record_hit(
                hits,
                reason="Cron persistence uses a high-frequency execution schedule",
                score=45,
                preview=_with_line_number(line_number, line),
                category="suspicious-schedule",
            )
            return


def _detect_mailto_abuse(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    match = MAILTO_REGEX.match(line)
    if not match:
        return

    value = match.group(1).strip().strip("'\"").lower()
    if value in {"", "root"}:
        return

    _record_hit(
        hits,
        reason="Cron configuration redirects MAILTO away from the default administrative recipient",
        score=10,
        preview=_with_line_number(line_number, line),
        category="mailto",
    )


def _detect_shell_abuse(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    match = SHELL_REGEX.match(line)
    if not match:
        return

    value = match.group(1).strip().strip("'\"")
    value_lower = value.lower()

    if _path_startswith_any(value_lower, TEMP_PATH_PATTERNS):
        _record_hit(
            hits,
            reason="Cron configuration sets SHELL to a temporary path",
            score=90,
            preview=_with_line_number(line_number, line),
            category="shell-temp",
        )
        return

    if USER_PATH_REGEX.search(value):
        _record_hit(
            hits,
            reason="Cron configuration sets SHELL to a user-controlled path",
            score=85,
            preview=_with_line_number(line_number, line),
            category="shell-user",
        )
        return

    if HIDDEN_PATH_REGEX.search(value):
        _record_hit(
            hits,
            reason="Cron configuration sets SHELL to a hidden path",
            score=80,
            preview=_with_line_number(line_number, line),
            category="shell-hidden",
        )


def _extract_cron_command(line: str) -> str | None:
    match = CRON_JOB_REGEX.match(line)
    if not match:
        return None

    command = match.group("command").strip()
    return command or None


def _detect_pipe_to_interpreter(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    if PIPE_TO_INTERPRETER_REGEX.search(line):
        _record_hit(
            hits,
            reason="Cron artifact pipes downloader output directly into an interpreter",
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
                reason="Cron artifact contains a high-risk interpreter one-liner",
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
                reason="Cron artifact contains reverse-shell or socket-based execution behavior",
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
            reason="Cron artifact decodes content and immediately executes it",
            score=95,
            preview=_with_line_number(line_number, line),
            category="decode-exec",
        )
        return

    for regex in ENCODED_EXEC_REGEXES:
        if regex.search(line):
            _record_hit(
                hits,
                reason="Cron artifact contains encoded payload handling logic",
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
    if _contains_high_risk_path(line_lower):
        if DIRECT_EXEC_REGEX.search(line):
            if _path_startswith_any(line_lower, TEMP_PATH_PATTERNS):
                _record_hit(
                    hits,
                    reason="Cron artifact executes content from a temporary path",
                    score=90,
                    preview=_with_line_number(line_number, line),
                    category="temp-exec",
                )
            elif USER_PATH_REGEX.search(line):
                _record_hit(
                    hits,
                    reason="Cron artifact executes content from a user-controlled path",
                    score=85,
                    preview=_with_line_number(line_number, line),
                    category="user-exec",
                )

    if HIDDEN_PATH_REGEX.search(line):
        _record_hit(
            hits,
            reason="Cron artifact references a hidden executable or payload path",
            score=75,
            preview=_with_line_number(line_number, line),
            category="hidden-path",
        )


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

    if _path_startswith_any(variable_value, TEMP_PATH_PATTERNS):
        _record_hit(
            hits,
            reason=f"Cron artifact sets {variable_name} to a temporary path",
            score=95,
            preview=_with_line_number(line_number, line),
            category="ld-hijack",
        )
    elif USER_PATH_REGEX.search(variable_value):
        _record_hit(
            hits,
            reason=f"Cron artifact sets {variable_name} to a user-controlled path",
            score=90,
            preview=_with_line_number(line_number, line),
            category="ld-hijack",
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

    for part in path_parts:
        if _path_startswith_any(part, TEMP_PATH_PATTERNS):
            _record_hit(
                hits,
                reason="Cron artifact modifies PATH to include a temporary directory",
                score=85,
                preview=_with_line_number(line_number, line),
                category="path-hijack",
            )
            return

        if USER_PATH_REGEX.search(part):
            _record_hit(
                hits,
                reason="Cron artifact modifies PATH to include a user-controlled directory",
                score=80,
                preview=_with_line_number(line_number, line),
                category="path-hijack",
            )
            return

        if HIDDEN_PATH_REGEX.search(part):
            _record_hit(
                hits,
                reason="Cron artifact modifies PATH to include a hidden directory",
                score=75,
                preview=_with_line_number(line_number, line),
                category="path-hijack",
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
                reason="Cron artifact contains stealth or privilege-manipulation logic",
                score=85,
                preview=_with_line_number(line_number, line),
                category="stealth-privilege",
            )
            return


def _detect_process_detach(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    for regex in PROCESS_DETACH_REGEXES:
        if regex.search(line):
            _record_hit(
                hits,
                reason="Cron artifact uses detached process execution behavior",
                score=25,
                preview=_with_line_number(line_number, line),
                category="process-detach",
            )
            return


def _detect_suspicious_direct_exec(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    if not DIRECT_EXEC_REGEX.search(line):
        return

    if _contains_high_risk_path(line_lower):
        if _path_startswith_any(line_lower, TEMP_PATH_PATTERNS):
            _record_hit(
                hits,
                reason="Cron artifact directly executes content from a temporary path",
                score=90,
                preview=_with_line_number(line_number, line),
                category="temp-exec",
            )
            return

        if USER_PATH_REGEX.search(line):
            _record_hit(
                hits,
                reason="Cron artifact directly executes content from a user-controlled path",
                score=85,
                preview=_with_line_number(line_number, line),
                category="user-exec",
            )
            return

    path_matches = re.findall(r"(/[^\s'\";|]+)", line)
    for matched_path in path_matches:
        if SUSPICIOUS_FILE_EXT_REGEX.search(matched_path):
            if _path_startswith_any(matched_path, TEMP_PATH_PATTERNS):
                _record_hit(
                    hits,
                    reason="Cron artifact executes a script or binary from a temporary path",
                    score=90,
                    preview=_with_line_number(line_number, line),
                    category="temp-exec",
                )
                return

            if USER_PATH_REGEX.search(matched_path):
                _record_hit(
                    hits,
                    reason="Cron artifact executes a script or binary from a user-controlled path",
                    score=85,
                    preview=_with_line_number(line_number, line),
                    category="user-exec",
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
        }
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Cron artifact combines download behavior with active execution logic",
            score=35,
            preview=None,
            category="compound-download-exec",
        )

    if "encoded" in categories and any(
        category in {"reverse-shell", "one-liner", "temp-exec", "user-exec", "decode-exec"}
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Cron artifact combines encoded payload handling with execution behavior",
            score=25,
            preview=None,
            category="compound-encoded-exec",
        )

    if "path-hijack" in categories and any(
        category in {"temp-exec", "user-exec", "stealth-privilege"}
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Cron artifact combines PATH hijacking with additional suspicious execution behavior",
            score=25,
            preview=None,
            category="compound-path-hijack",
        )

    if "suspicious-schedule" in categories and any(
        category in {"temp-exec", "user-exec", "download-exec", "reverse-shell"}
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Cron persistence uses a suspicious schedule combined with high-risk execution behavior",
            score=25,
            preview=None,
            category="compound-schedule-exec",
        )


def _finalize_finding(path: Path, hits: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    high_confidence_categories = {
        "temp-target",
        "user-target",
        "hidden-target",
        "ownership",
        "permissions",
        "binary",
        "download-exec",
        "reverse-shell",
        "decode-exec",
        "temp-exec",
        "user-exec",
        "ld-hijack",
        "path-hijack",
        "stealth-privilege",
        "hidden-path",
        "suspicious-schedule",
        "compound-download-exec",
        "compound-encoded-exec",
        "compound-path-hijack",
        "compound-schedule-exec",
    }

    low_signal_only_categories = {
        "download",
        "download-to-risk-path",
        "encoded",
        "process-detach",
        "direct-exec",
    }
    return shared_finalize_finding(
        path,
        hits,
        high_confidence_categories=high_confidence_categories,
        low_signal_only_categories=low_signal_only_categories,
    )


def _record_hit(
    hits: dict[str, dict[str, Any]],
    reason: str,
    score: int,
    preview: str | None,
    category: str,
) -> None:
    shared_record_hit(hits, reason, score, preview, category)


def _build_collect_record(path: Path, hash_files: bool = False) -> dict[str, Any]:
    return shared_build_collect_record(path, hash_files=hash_files)


def _safe_iterdir(path: Path) -> list[Path]:
    try:
        return list(path.iterdir())
    except Exception:
        return []


def _safe_walk(base: Path) -> list[Path]:
    return shared_safe_walk(base)


def _safe_stat(path: Path):
    return shared_safe_stat(path)


def _safe_lstat(path: Path):
    return shared_safe_lstat(path)


def _owner_from_uid(uid: int) -> str:
    return shared_owner_from_uid(uid)


def _path_startswith_any(path_value: str, prefixes: tuple[str, ...]) -> bool:
    return shared_path_startswith_any(path_value, prefixes)


def _contains_high_risk_path(line_lower: str) -> bool:
    return shared_contains_high_risk_path(
        line_lower,
        temp_path_patterns=TEMP_PATH_PATTERNS,
        user_path_regex=USER_PATH_REGEX,
    )


def _with_line_number(line_number: int, line: str) -> str:
    return shared_with_line_number(line_number, line)


def _is_metadata_line(line: str) -> bool:
    stripped = line.strip()
    return any(stripped.startswith(prefix) for prefix in CRON_METADATA_PREFIXES)


def _severity(score: int) -> str:
    return severity_from_score(score)
