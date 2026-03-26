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

SYSTEMD_PATHS = [
    Path("/etc/systemd/system"),
    Path("/lib/systemd/system"),
    Path("/usr/lib/systemd/system"),
    Path("/run/systemd/system"),
    Path.home() / ".config/systemd/user",
    Path("/etc/systemd/user"),
    Path("/usr/lib/systemd/user"),
]

UNIT_FILE_SUFFIXES = (
    ".service",
    ".socket",
    ".timer",
    ".path",
    ".mount",
    ".automount",
    ".target",
)

DROPIN_SUFFIX = ".d"

TEMP_PATH_PATTERNS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/shm/",
)

STANDARD_SYSTEM_PREFIXES = (
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/lib/",
    "/lib/",
    "/lib/systemd/",
    "/usr/lib/systemd/",
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
    r"\bPATH\s*=\s*['\"]?([^'\"\n]+)",
    re.IGNORECASE,
)

PROCESS_DETACH_REGEXES = [
    re.compile(r"\bnohup\b", re.IGNORECASE),
    re.compile(r"\bsetsid\b", re.IGNORECASE),
    re.compile(r"\bdisown\b", re.IGNORECASE),
]

EXEC_KEY_REGEX = re.compile(
    r"^(ExecStart|ExecStartPre|ExecStartPost|ExecStop|ExecStopPost|ExecReload)\s*=\s*(.+)$",
    re.IGNORECASE,
)

ENV_KEY_REGEX = re.compile(r"^Environment\s*=\s*(.+)$", re.IGNORECASE)
ENV_FILE_KEY_REGEX = re.compile(r"^EnvironmentFile\s*=\s*(.+)$", re.IGNORECASE)
WORKING_DIR_REGEX = re.compile(r"^WorkingDirectory\s*=\s*(.+)$", re.IGNORECASE)
USER_KEY_REGEX = re.compile(r"^User\s*=\s*(.+)$", re.IGNORECASE)
GROUP_KEY_REGEX = re.compile(r"^Group\s*=\s*(.+)$", re.IGNORECASE)

TIMER_KEYS = {
    "OnActiveSec",
    "OnBootSec",
    "OnStartupSec",
    "OnUnitActiveSec",
    "OnUnitInactiveSec",
    "OnCalendar",
}

PERSISTENT_TIMER_REGEX = re.compile(r"^Persistent\s*=\s*true$", re.IGNORECASE)

UNIT_DIRECTIVE_REGEX = re.compile(r"^([A-Za-z][A-Za-z0-9]+)\s*=\s*(.+)$")
WANTED_BY_REGEX = re.compile(r"^WantedBy\s*=\s*(.+)$", re.IGNORECASE)


def analyze_systemd_locations() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in SYSTEMD_PATHS:
        if not path_exists(base):
            continue

        if base.is_dir():
            for child in _safe_walk_systemd(base):
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


def collect_systemd_locations(hash_files: bool = False) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in SYSTEMD_PATHS:
        if not path_exists(base):
            continue

        if base.is_dir():
            for child in _safe_walk_systemd(base):
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
            reason="Systemd symlink target points into a temporary execution path",
            score=95,
            preview=f"symlink -> {target_str}",
            category="temp-target",
        )

    if USER_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="Systemd symlink target points into a user-controlled path",
            score=90,
            preview=f"symlink -> {target_str}",
            category="user-target",
        )

    if HIDDEN_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="Systemd symlink target references a hidden path",
            score=75,
            preview=f"symlink -> {target_str}",
            category="hidden-target",
        )

    stat_info = _safe_lstat(path)
    if stat_info and stat_info.st_uid != 0:
        owner_name = _owner_from_uid(stat_info.st_uid)
        _record_hit(
            hits,
            reason="Systemd symlink is owned by a non-root account",
            score=75,
            preview=f"owner={owner_name}",
            category="ownership",
        )

    return _finalize_finding(path, hits)


def _analyze_file(path: Path) -> dict[str, Any] | None:
    hits: dict[str, dict[str, Any]] = {}
    lower_path = str(path).lower()

    stat_info = _safe_stat(path)
    if stat_info:
        mode = stat_info.st_mode & 0o777
        owner_name = _owner_from_uid(stat_info.st_uid)

        if stat_info.st_uid != 0:
            _record_hit(
                hits,
                reason="Systemd unit is owned by a non-root account",
                score=80,
                preview=f"owner={owner_name}",
                category="ownership",
            )

        if mode & 0o002:
            _record_hit(
                hits,
                reason="Systemd unit is world-writable",
                score=100,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )
        elif mode & 0o020:
            _record_hit(
                hits,
                reason="Systemd unit is group-writable",
                score=60,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )

    if "/user/" in lower_path or "/.config/systemd/user/" in lower_path:
        _record_hit(
            hits,
            reason="Systemd persistence is defined in a user-level unit path",
            score=35,
            preview=str(path),
            category="user-unit-location",
        )

    if ".service.d/" in lower_path or lower_path.endswith(".conf"):
        _record_hit(
            hits,
            reason="Systemd unit uses a drop-in override file",
            score=25,
            preview=str(path),
            category="dropin",
        )

    try:
        raw = path.read_bytes()
    except Exception:
        return _finalize_finding(path, hits)

    if b"\x00" in raw[:4096]:
        _record_hit(
            hits,
            reason="Systemd unit contains binary content instead of expected text directives",
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
        if stripped.startswith("#") or stripped.startswith(";"):
            continue

        _detect_exec_directives(hits, stripped, line_number)
        _detect_environment_directives(hits, stripped, line_number)
        _detect_working_directory(hits, stripped, line_number)
        _detect_user_group_anomalies(hits, stripped, line_number)
        _detect_timer_persistence(hits, stripped, line_number)
        _detect_inline_payload_behaviors(hits, stripped, line_number)
        _detect_ld_hijack(hits, stripped, line_number)
        _detect_path_hijack(hits, stripped, line_number)
        _detect_stealth_or_privilege_changes(hits, stripped, stripped.lower(), line_number)
        _detect_process_detach(hits, stripped, line_number)

    _apply_compound_behavior_bonuses(hits)

    return _finalize_finding(path, hits)

def _detect_exec_directives(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    match = EXEC_KEY_REGEX.match(line)
    if not match:
        return

    directive = match.group(1)
    value = match.group(2).strip()
    value_lower = value.lower()

    if _contains_high_risk_path(value_lower):
        if _path_startswith_any(value_lower, TEMP_PATH_PATTERNS):
            _record_hit(
                hits,
                reason=f"Systemd {directive} executes from a temporary path",
                score=95,
                preview=_with_line_number(line_number, line),
                category="temp-exec",
            )
        elif USER_PATH_REGEX.search(value):
            _record_hit(
                hits,
                reason=f"Systemd {directive} executes from a user-controlled path",
                score=90,
                preview=_with_line_number(line_number, line),
                category="user-exec",
            )

    if HIDDEN_PATH_REGEX.search(value):
        _record_hit(
            hits,
            reason=f"Systemd {directive} references a hidden payload path",
            score=80,
            preview=_with_line_number(line_number, line),
            category="hidden-path",
        )

    executable_paths = re.findall(r"(/[^\s'\";|]+)", value)
    for executable_path in executable_paths:
        if executable_path.startswith(STANDARD_SYSTEM_PREFIXES):
            continue

        if _path_startswith_any(executable_path.lower(), TEMP_PATH_PATTERNS):
            continue

        if USER_PATH_REGEX.search(executable_path):
            continue

        _record_hit(
            hits,
            reason=f"Systemd {directive} references a non-standard executable path",
            score=55,
            preview=_with_line_number(line_number, line),
            category="nonstandard-exec",
        )
        break


def _detect_environment_directives(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    env_match = ENV_KEY_REGEX.match(line)
    if env_match:
        value = env_match.group(1).strip()
        value_lower = value.lower()

        if "ld_preload=" in value_lower or "ld_library_path=" in value_lower:
            if _contains_high_risk_path(value_lower):
                _record_hit(
                    hits,
                    reason="Systemd Environment= defines LD preload behavior using a high-risk path",
                    score=95,
                    preview=_with_line_number(line_number, line),
                    category="ld-hijack",
                )

        if "path=" in value_lower and _contains_high_risk_path(value_lower):
            _record_hit(
                hits,
                reason="Systemd Environment= modifies PATH to include a high-risk path",
                score=85,
                preview=_with_line_number(line_number, line),
                category="path-hijack",
            )

    env_file_match = ENV_FILE_KEY_REGEX.match(line)
    if env_file_match:
        value = env_file_match.group(1).strip().lstrip("-").strip()
        value_lower = value.lower()

        if _path_startswith_any(value_lower, TEMP_PATH_PATTERNS):
            _record_hit(
                hits,
                reason="Systemd EnvironmentFile= references a temporary path",
                score=95,
                preview=_with_line_number(line_number, line),
                category="envfile-temp",
            )
        elif USER_PATH_REGEX.search(value):
            _record_hit(
                hits,
                reason="Systemd EnvironmentFile= references a user-controlled path",
                score=90,
                preview=_with_line_number(line_number, line),
                category="envfile-user",
            )
        elif HIDDEN_PATH_REGEX.search(value):
            _record_hit(
                hits,
                reason="Systemd EnvironmentFile= references a hidden path",
                score=80,
                preview=_with_line_number(line_number, line),
                category="envfile-hidden",
            )


def _detect_working_directory(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    match = WORKING_DIR_REGEX.match(line)
    if not match:
        return

    value = match.group(1).strip()
    value_lower = value.lower()

    if _path_startswith_any(value_lower, TEMP_PATH_PATTERNS):
        _record_hit(
            hits,
            reason="Systemd WorkingDirectory points into a temporary path",
            score=80,
            preview=_with_line_number(line_number, line),
            category="workdir-temp",
        )
    elif USER_PATH_REGEX.search(value):
        _record_hit(
            hits,
            reason="Systemd WorkingDirectory points into a user-controlled path",
            score=75,
            preview=_with_line_number(line_number, line),
            category="workdir-user",
        )
    elif HIDDEN_PATH_REGEX.search(value):
        _record_hit(
            hits,
            reason="Systemd WorkingDirectory references a hidden path",
            score=70,
            preview=_with_line_number(line_number, line),
            category="workdir-hidden",
        )


def _detect_user_group_anomalies(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    user_match = USER_KEY_REGEX.match(line)
    if user_match:
        value = user_match.group(1).strip()
        if value.lower() not in {"root", "nobody", "systemd-network", "systemd-resolve", "www-data"}:
            _record_hit(
                hits,
                reason="Systemd unit runs under a non-standard user context",
                score=25,
                preview=_with_line_number(line_number, line),
                category="user-context",
            )

    group_match = GROUP_KEY_REGEX.match(line)
    if group_match:
        value = group_match.group(1).strip()
        if value.lower() not in {"root", "nogroup", "www-data"}:
            _record_hit(
                hits,
                reason="Systemd unit runs under a non-standard group context",
                score=20,
                preview=_with_line_number(line_number, line),
                category="group-context",
            )


def _detect_timer_persistence(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    match = UNIT_DIRECTIVE_REGEX.match(line)
    if not match:
        return

    key = match.group(1)
    value = match.group(2).strip()

    if key in TIMER_KEYS:
        _record_hit(
            hits,
            reason=f"Systemd timer persistence uses {key}",
            score=20,
            preview=_with_line_number(line_number, line),
            category="timer",
        )

        if key == "OnCalendar" and any(token in value.lower() for token in ("*:*", "minutely", "hourly")):
            _record_hit(
                hits,
                reason="Systemd timer uses a frequent calendar schedule",
                score=35,
                preview=_with_line_number(line_number, line),
                category="timer-frequent",
            )

    if PERSISTENT_TIMER_REGEX.match(line):
        _record_hit(
            hits,
            reason="Systemd timer is configured as Persistent=true",
            score=25,
            preview=_with_line_number(line_number, line),
            category="timer-persistent",
        )


def _detect_inline_payload_behaviors(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    line_lower = line.lower()

    has_download_tool = bool(DOWNLOAD_TOOL_REGEX.search(line))
    has_url = bool(URL_REGEX.search(line))

    if has_download_tool and has_url:
        _record_hit(
            hits,
            reason="Systemd unit contains network download behavior",
            score=60,
            preview=_with_line_number(line_number, line),
            category="download",
        )

    if PIPE_TO_INTERPRETER_REGEX.search(line):
        _record_hit(
            hits,
            reason="Systemd unit downloads and executes payload inline",
            score=100,
            preview=_with_line_number(line_number, line),
            category="download-exec",
        )

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
                reason="Systemd unit contains a high-risk interpreter one-liner",
                score=70,
                preview=_with_line_number(line_number, line),
                category="one-liner",
            )

    for regex in SOCKET_IMPLANT_REGEXES:
        if regex.search(line):
            _record_hit(
                hits,
                reason="Systemd unit contains reverse-shell or socket-based execution behavior",
                score=100,
                preview=_with_line_number(line_number, line),
                category="reverse-shell",
            )
            break

    if ENCODED_TO_EXEC_REGEX.search(line):
        _record_hit(
            hits,
            reason="Systemd unit decodes content and immediately executes it",
            score=95,
            preview=_with_line_number(line_number, line),
            category="decode-exec",
        )
        return

    for regex in ENCODED_EXEC_REGEXES:
        if regex.search(line):
            _record_hit(
                hits,
                reason="Systemd unit contains encoded payload handling logic",
                score=45,
                preview=_with_line_number(line_number, line),
                category="encoded",
            )
            break


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
            reason=f"Systemd unit sets {variable_name} to a temporary path",
            score=95,
            preview=_with_line_number(line_number, line),
            category="ld-hijack",
        )
    elif USER_PATH_REGEX.search(variable_value):
        _record_hit(
            hits,
            reason=f"Systemd unit sets {variable_name} to a user-controlled path",
            score=90,
            preview=_with_line_number(line_number, line),
            category="ld-hijack",
        )
    elif HIDDEN_PATH_REGEX.search(variable_value):
        _record_hit(
            hits,
            reason=f"Systemd unit sets {variable_name} to a hidden path",
            score=85,
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
                reason="Systemd unit modifies PATH to include a temporary directory",
                score=85,
                preview=_with_line_number(line_number, line),
                category="path-hijack",
            )
            return

        if USER_PATH_REGEX.search(part):
            _record_hit(
                hits,
                reason="Systemd unit modifies PATH to include a user-controlled directory",
                score=80,
                preview=_with_line_number(line_number, line),
                category="path-hijack",
            )
            return

        if HIDDEN_PATH_REGEX.search(part):
            _record_hit(
                hits,
                reason="Systemd unit modifies PATH to include a hidden directory",
                score=75,
                preview=_with_line_number(line_number, line),
                category="path-hijack",
            )
            return


def _detect_dropin_override_risk(
    hits: dict[str, dict[str, Any]],
    path: Path,
) -> None:
    path_str = str(path)

    if ".service.d/" in path_str or ".socket.d/" in path_str or ".timer.d/" in path_str:
        _record_hit(
            hits,
            reason="Systemd persistence is implemented through a drop-in override",
            score=20,
            preview=path_str,
            category="dropin",
        )

    if path.name.lower() == "override.conf":
        _record_hit(
            hits,
            reason="Systemd persistence uses override.conf",
            score=20,
            preview=path_str,
            category="override",
        )


def _detect_unit_install_behavior(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    match = WANTED_BY_REGEX.match(line)
    if not match:
        return

    value = match.group(1).strip().lower()
    suspicious_targets = {
        "multi-user.target",
        "default.target",
        "graphical.target",
        "timers.target",
    }

    if value in suspicious_targets:
        _record_hit(
            hits,
            reason=f"Systemd unit is configured to start with {value}",
            score=15,
            preview=_with_line_number(line_number, line),
            category="wantedby",
        )


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
                reason="Systemd unit contains stealth or privilege-manipulation logic",
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
                reason="Systemd unit uses detached process execution behavior",
                score=20,
                preview=_with_line_number(line_number, line),
                category="process-detach",
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
            reason="Systemd unit combines download behavior with active execution logic",
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
            reason="Systemd unit combines encoded payload handling with execution behavior",
            score=25,
            preview=None,
            category="compound-encoded-exec",
        )

    if "path-hijack" in categories and any(
        category in {"temp-exec", "user-exec", "stealth-privilege", "nonstandard-exec"}
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Systemd unit combines PATH hijacking with suspicious execution behavior",
            score=25,
            preview=None,
            category="compound-path-hijack",
        )

    if "timer" in categories and any(
        category in {"timer-frequent", "timer-persistent", "temp-exec", "user-exec"}
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Systemd timer persistence is paired with suspicious execution characteristics",
            score=20,
            preview=None,
            category="compound-timer",
        )

    if "dropin" in categories and any(
        category in {
            "temp-exec",
            "user-exec",
            "hidden-path",
            "download-exec",
            "reverse-shell",
            "ld-hijack",
            "path-hijack",
        }
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Systemd drop-in override modifies execution behavior in a suspicious way",
            score=25,
            preview=None,
            category="compound-dropin",
        )


def _finalize_finding(path: Path, hits: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    high_confidence_categories = {
        "temp-exec",
        "user-exec",
        "hidden-path",
        "download-exec",
        "reverse-shell",
        "decode-exec",
        "ld-hijack",
        "path-hijack",
        "envfile-temp",
        "envfile-user",
        "envfile-hidden",
        "temp-target",
        "user-target",
        "hidden-target",
        "binary",
        "stealth-privilege",
    }

    low_signal_only_categories = {
        "timer",
        "timer-frequent",
        "timer-persistent",
        "dropin",
        "override",
        "wantedby",
        "user-context",
        "group-context",
        "process-detach",
        "nonstandard-exec",
        "workdir-temp",
        "workdir-user",
        "workdir-hidden",
    }

    return shared_finalize_finding(
        path,
        hits,
        high_confidence_categories=high_confidence_categories,
        low_signal_only_categories=low_signal_only_categories,
        non_behavioral_categories={"ownership", "permissions"},
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


def _safe_walk_systemd(base: Path) -> list[Path]:
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


def _severity(score: int) -> str:
    return severity_from_score(score)
