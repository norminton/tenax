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
    severity_from_score,
    with_line_number as shared_with_line_number,
)
from tenax.utils import is_file_safe, path_exists

SUDOERS_PATHS = [
    Path("/etc/sudoers"),
    Path("/etc/sudoers.d"),
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
    r"\b(?:PATH|secure_path)\s*=\s*['\"]?([^'\"\n]+)",
    re.IGNORECASE,
)

NOPASSWD_ALL_REGEX = re.compile(r"\bNOPASSWD\s*:\s*ALL\b", re.IGNORECASE)
NOPASSWD_REGEX = re.compile(r"\bNOPASSWD\s*:", re.IGNORECASE)
NOAUTH_REGEX = re.compile(r"\b!authenticate\b", re.IGNORECASE)
SETENV_REGEX = re.compile(r"\bSETENV\b", re.IGNORECASE)
ALL_ALL_REGEX = re.compile(r"\bALL\s*=\s*\(ALL(?::ALL)?\)\s*ALL\b", re.IGNORECASE)

ENV_KEEP_REGEX = re.compile(r"^\s*Defaults\b.*\benv_keep\s*[+]?=", re.IGNORECASE)
ENV_CHECK_REGEX = re.compile(r"^\s*Defaults\b.*\benv_check\s*[+]?=", re.IGNORECASE)
SECURE_PATH_REGEX = re.compile(r"^\s*Defaults\b.*\bsecure_path\s*=", re.IGNORECASE)

INCLUDE_REGEX = re.compile(r"^\s*#?(include|includedir)\s+(.+)$", re.IGNORECASE)
CMND_ALIAS_REGEX = re.compile(r"^\s*Cmnd_Alias\s+([A-Za-z0-9_]+)\s*=\s*(.+)$", re.IGNORECASE)
DEFAULTS_REGEX = re.compile(r"^\s*Defaults(?::[^\s=]+)?\s+(.+)$", re.IGNORECASE)
PRIVILEGE_RULE_COMMANDS_REGEX = re.compile(
    r"""
    \)\s*
    (?:
        NOPASSWD|PASSWD|SETENV|NOSETENV
    )?
    \s*:
    \s*(?P<commands>.+)$
    """,
    re.IGNORECASE | re.VERBOSE,
)

DIRECT_EXEC_REGEX = re.compile(
    r"""
    \b(
        sh|bash|dash|ash|ksh|zsh|
        python|python2|python3|perl|ruby|php|
        env|exec
    )\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

SUSPICIOUS_FILE_EXT_REGEX = re.compile(
    r"\.(sh|py|pl|rb|php|elf|bin|out|so)$",
    re.IGNORECASE,
)

SUDOERS_METADATA_PREFIXES = (
    "user_alias ",
    "runas_alias ",
    "host_alias ",
)


def analyze_sudoers_locations() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in SUDOERS_PATHS:
        if not path_exists(base):
            continue

        if base.is_dir():
            for child in _safe_iterdir(base):
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


def collect_sudoers_locations(hash_files: bool = False) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in SUDOERS_PATHS:
        if not path_exists(base):
            continue

        if base.is_dir():
            for child in _safe_iterdir(base):
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
            reason="sudoers artifact symlink points to a temporary path",
            score=95,
            preview=f"symlink -> {target_str}",
            category="temp-target",
        )

    if USER_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="sudoers artifact symlink points to a user-controlled path",
            score=90,
            preview=f"symlink -> {target_str}",
            category="user-target",
        )

    if HIDDEN_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="sudoers artifact symlink points to a hidden path",
            score=80,
            preview=f"symlink -> {target_str}",
            category="hidden-target",
        )

    stat_info = _safe_lstat(path)
    if stat_info and stat_info.st_uid != 0:
        _record_hit(
            hits,
            reason="sudoers artifact symlink is owned by a non-root account",
            score=75,
            preview=f"owner={_owner_from_uid(stat_info.st_uid)}",
            category="ownership",
        )

    return _finalize_finding(path, hits)


def _analyze_file(path: Path) -> dict[str, Any] | None:
    hits: dict[str, dict[str, Any]] = {}
    path_name = path.name.lower()

    stat_info = _safe_stat(path)
    if stat_info:
        mode = stat_info.st_mode & 0o777

        if stat_info.st_uid != 0:
            _record_hit(
                hits,
                reason="sudoers artifact is owned by a non-root account",
                score=90,
                preview=f"owner={_owner_from_uid(stat_info.st_uid)}",
                category="ownership",
            )

        if mode & 0o002:
            _record_hit(
                hits,
                reason="sudoers artifact is world-writable",
                score=100,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )
        elif mode & 0o020:
            _record_hit(
                hits,
                reason="sudoers artifact is group-writable",
                score=65,
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
            reason="sudoers artifact contains binary content instead of expected text configuration",
            score=75,
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

        if stripped.startswith("#") and not INCLUDE_REGEX.match(stripped):
            continue

        if _is_metadata_line(stripped):
            continue

        _detect_include_risk(hits, stripped, line_lower, line_number)
        _detect_privilege_delegation_risk(hits, stripped, line_lower, line_number)
        _detect_defaults_abuse(hits, stripped, line_lower, line_number)
        _detect_cmnd_alias_abuse(hits, stripped, line_lower, line_number)
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

def _detect_include_risk(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    match = INCLUDE_REGEX.match(line)
    if not match:
        return

    directive = match.group(1).lower()
    value = match.group(2).strip()
    value_lower = value.lower()

    _record_hit(
        hits,
        reason=f"sudoers uses {directive} directive",
        score=10,
        preview=_with_line_number(line_number, line),
        category=f"include-{directive}",
    )

    if _path_startswith_any(value_lower, TEMP_PATH_PATTERNS):
        _record_hit(
            hits,
            reason=f"sudoers {directive} references a temporary path",
            score=95,
            preview=_with_line_number(line_number, line),
            category=f"include-{directive}-temp",
        )
        return

    if USER_PATH_REGEX.search(value):
        _record_hit(
            hits,
            reason=f"sudoers {directive} references a user-controlled path",
            score=90,
            preview=_with_line_number(line_number, line),
            category=f"include-{directive}-user",
        )
        return

    if HIDDEN_PATH_REGEX.search(value):
        _record_hit(
            hits,
            reason=f"sudoers {directive} references a hidden path",
            score=80,
            preview=_with_line_number(line_number, line),
            category=f"include-{directive}-hidden",
        )
        return


def _detect_privilege_delegation_risk(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    if NOPASSWD_ALL_REGEX.search(line):
        _record_hit(
            hits,
            reason="sudoers grants NOPASSWD: ALL",
            score=100,
            preview=_with_line_number(line_number, line),
            category="nopasswd-all",
        )
        return

    if ALL_ALL_REGEX.search(line):
        _record_hit(
            hits,
            reason="sudoers grants ALL=(ALL) ALL privileges",
            score=55,
            preview=_with_line_number(line_number, line),
            category="all-all",
        )

    if NOPASSWD_REGEX.search(line):
        _record_hit(
            hits,
            reason="sudoers grants NOPASSWD privileges",
            score=70,
            preview=_with_line_number(line_number, line),
            category="nopasswd",
        )

    if NOAUTH_REGEX.search(line):
        _record_hit(
            hits,
            reason="sudoers disables authentication with !authenticate",
            score=95,
            preview=_with_line_number(line_number, line),
            category="noauthenticate",
        )

    if SETENV_REGEX.search(line):
        _record_hit(
            hits,
            reason="sudoers grants SETENV capability",
            score=60,
            preview=_with_line_number(line_number, line),
            category="setenv",
        )

    command_match = PRIVILEGE_RULE_COMMANDS_REGEX.search(line)
    if command_match:
        _detect_privilege_rule_command_paths(
            hits,
            command_match.group("commands").strip(),
            line,
            line_number,
        )


def _detect_defaults_abuse(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    defaults_match = DEFAULTS_REGEX.match(line)
    if not defaults_match:
        return

    value = defaults_match.group(1).strip()
    value_lower = value.lower()

    if ENV_KEEP_REGEX.match(line):
        _record_hit(
            hits,
            reason="sudoers modifies env_keep defaults",
            score=25,
            preview=_with_line_number(line_number, line),
            category="defaults-env-keep",
        )

        if "ld_preload" in value_lower or "ld_library_path" in value_lower:
            _record_hit(
                hits,
                reason="sudoers env_keep preserves LD preload variables",
                score=95,
                preview=_with_line_number(line_number, line),
                category="defaults-env-keep-ld",
            )

        if "path" in value_lower:
            _record_hit(
                hits,
                reason="sudoers env_keep preserves PATH-like variables",
                score=65,
                preview=_with_line_number(line_number, line),
                category="defaults-env-keep-path",
            )

    if ENV_CHECK_REGEX.match(line):
        _record_hit(
            hits,
            reason="sudoers modifies env_check defaults",
            score=20,
            preview=_with_line_number(line_number, line),
            category="defaults-env-check",
        )

    if SECURE_PATH_REGEX.match(line):
        _record_hit(
            hits,
            reason="sudoers defines secure_path",
            score=20,
            preview=_with_line_number(line_number, line),
            category="secure-path",
        )

        path_match = PATH_HIJACK_REGEX.search(line)
        if path_match:
            path_value = path_match.group(1).strip()
            path_parts = [part.strip() for part in path_value.split(":") if part.strip()]

            for part in path_parts:
                part_lower = part.lower()

                if _path_startswith_any(part_lower, TEMP_PATH_PATTERNS):
                    _record_hit(
                        hits,
                        reason="sudoers secure_path includes a temporary directory",
                        score=90,
                        preview=_with_line_number(line_number, line),
                        category="secure-path-temp",
                    )
                    return

                if USER_PATH_REGEX.search(part):
                    _record_hit(
                        hits,
                        reason="sudoers secure_path includes a user-controlled directory",
                        score=85,
                        preview=_with_line_number(line_number, line),
                        category="secure-path-user",
                    )
                    return

                if HIDDEN_PATH_REGEX.search(part):
                    _record_hit(
                        hits,
                        reason="sudoers secure_path includes a hidden directory",
                        score=80,
                        preview=_with_line_number(line_number, line),
                        category="secure-path-hidden",
                    )
                    return


def _detect_cmnd_alias_abuse(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    match = CMND_ALIAS_REGEX.match(line)
    if not match:
        return

    alias_name = match.group(1)
    alias_value = match.group(2).strip()
    alias_value_lower = alias_value.lower()

    _record_hit(
        hits,
        reason=f"sudoers defines Cmnd_Alias {alias_name}",
        score=15,
        preview=_with_line_number(line_number, line),
        category="cmnd-alias",
    )

    if _contains_high_risk_path(alias_value_lower):
        if _path_startswith_any(alias_value_lower, TEMP_PATH_PATTERNS):
            _record_hit(
                hits,
                reason=f"Cmnd_Alias {alias_name} references a temporary path",
                score=95,
                preview=_with_line_number(line_number, line),
                category="cmnd-alias-temp",
            )
            return

        if USER_PATH_REGEX.search(alias_value):
            _record_hit(
                hits,
                reason=f"Cmnd_Alias {alias_name} references a user-controlled path",
                score=90,
                preview=_with_line_number(line_number, line),
                category="cmnd-alias-user",
            )
            return

    if HIDDEN_PATH_REGEX.search(alias_value):
        _record_hit(
            hits,
            reason=f"Cmnd_Alias {alias_name} references a hidden path",
            score=80,
            preview=_with_line_number(line_number, line),
            category="cmnd-alias-hidden",
        )
        return

    if DOWNLOAD_TOOL_REGEX.search(alias_value) and URL_REGEX.search(alias_value):
        _record_hit(
            hits,
            reason=f"Cmnd_Alias {alias_name} contains network retrieval behavior",
            score=75,
            preview=_with_line_number(line_number, line),
            category="cmnd-alias-download",
        )
        return

    if PIPE_TO_INTERPRETER_REGEX.search(alias_value):
        _record_hit(
            hits,
            reason=f"Cmnd_Alias {alias_name} downloads and executes payload inline",
            score=100,
            preview=_with_line_number(line_number, line),
            category="cmnd-alias-download-exec",
        )


def _detect_privilege_rule_command_paths(
    hits: dict[str, dict[str, Any]],
    commands: str,
    line: str,
    line_number: int,
) -> None:
    for matched_path in re.findall(r"(/[^\s'\";|,]+)", commands):
        matched_lower = matched_path.lower()

        if _path_startswith_any(matched_lower, TEMP_PATH_PATTERNS):
            _record_hit(
                hits,
                reason="sudoers delegated command list includes a temporary-path command",
                score=90,
                preview=_with_line_number(line_number, line),
                category="temp-exec",
            )
            return

        if USER_PATH_REGEX.search(matched_path):
            _record_hit(
                hits,
                reason="sudoers delegated command list includes a user-controlled command path",
                score=85,
                preview=_with_line_number(line_number, line),
                category="user-exec",
            )
            return

        if HIDDEN_PATH_REGEX.search(matched_path):
            _record_hit(
                hits,
                reason="sudoers delegated command list includes a hidden command path",
                score=80,
                preview=_with_line_number(line_number, line),
                category="hidden-exec",
            )
            return
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
            reason="sudoers artifact downloads content from a remote URL",
            score=60,
            preview=_with_line_number(line_number, line),
            category="download",
        )

    if has_download_tool and any(token in line_lower for token in ("-o ", "--output", "> /", ">> /")):
        if _contains_high_risk_path(line_lower):
            _record_hit(
                hits,
                reason="sudoers artifact downloads remote content into a high-risk local path",
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
            reason="sudoers artifact pipes downloader output directly into an interpreter",
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
                reason="sudoers artifact contains a high-risk interpreter one-liner",
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
                reason="sudoers artifact contains reverse-shell or socket-based execution behavior",
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
            reason="sudoers artifact decodes content and immediately executes it",
            score=95,
            preview=_with_line_number(line_number, line),
            category="decode-exec",
        )
        return

    for regex in ENCODED_EXEC_REGEXES:
        if regex.search(line):
            _record_hit(
                hits,
                reason="sudoers artifact contains encoded payload handling logic",
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
    path_matches = re.findall(r"(/[^\s'\";|,]+)", line)
    for matched_path in path_matches:
        matched_lower = matched_path.lower()

        if _path_startswith_any(matched_lower, TEMP_PATH_PATTERNS):
            _record_hit(
                hits,
                reason="sudoers artifact delegates execution to a temporary-path command",
                score=90,
                preview=_with_line_number(line_number, line),
                category="temp-exec",
            )
            return

        if USER_PATH_REGEX.search(matched_path):
            _record_hit(
                hits,
                reason="sudoers artifact delegates execution to a user-controlled command path",
                score=85,
                preview=_with_line_number(line_number, line),
                category="user-exec",
            )
            return

        if HIDDEN_PATH_REGEX.search(matched_path):
            _record_hit(
                hits,
                reason="sudoers artifact references a hidden executable or payload path",
                score=80,
                preview=_with_line_number(line_number, line),
                category="hidden-exec",
            )
            return

        if SUSPICIOUS_FILE_EXT_REGEX.search(matched_path):
            if _path_startswith_any(matched_lower, TEMP_PATH_PATTERNS):
                _record_hit(
                    hits,
                    reason="sudoers artifact executes a script or binary from a temporary path",
                    score=90,
                    preview=_with_line_number(line_number, line),
                    category="temp-exec",
                )
                return

            if USER_PATH_REGEX.search(matched_path):
                _record_hit(
                    hits,
                    reason="sudoers artifact executes a script or binary from a user-controlled path",
                    score=85,
                    preview=_with_line_number(line_number, line),
                    category="user-exec",
                )
                return

            if HIDDEN_PATH_REGEX.search(matched_path):
                _record_hit(
                    hits,
                    reason="sudoers artifact executes a script or binary from a hidden path",
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

    if _path_startswith_any(variable_value.lower(), TEMP_PATH_PATTERNS):
        _record_hit(
            hits,
            reason=f"sudoers artifact sets {variable_name} to a temporary path",
            score=95,
            preview=_with_line_number(line_number, line),
            category="ld-hijack",
        )
        return

    if USER_PATH_REGEX.search(variable_value):
        _record_hit(
            hits,
            reason=f"sudoers artifact sets {variable_name} to a user-controlled path",
            score=90,
            preview=_with_line_number(line_number, line),
            category="ld-hijack",
        )
        return

    if HIDDEN_PATH_REGEX.search(variable_value):
        _record_hit(
            hits,
            reason=f"sudoers artifact sets {variable_name} to a hidden path",
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
        part_lower = part.lower()

        if _path_startswith_any(part_lower, TEMP_PATH_PATTERNS):
            _record_hit(
                hits,
                reason="sudoers artifact modifies PATH to include a temporary directory",
                score=85,
                preview=_with_line_number(line_number, line),
                category="path-hijack",
            )
            return

        if USER_PATH_REGEX.search(part):
            _record_hit(
                hits,
                reason="sudoers artifact modifies PATH to include a user-controlled directory",
                score=80,
                preview=_with_line_number(line_number, line),
                category="path-hijack",
            )
            return

        if HIDDEN_PATH_REGEX.search(part):
            _record_hit(
                hits,
                reason="sudoers artifact modifies PATH to include a hidden directory",
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
                reason="sudoers artifact contains stealth or privilege-manipulation logic",
                score=85,
                preview=_with_line_number(line_number, line),
                category="stealth-privilege",
            )
            return

def _apply_compound_behavior_bonuses(hits: dict[str, dict[str, Any]]) -> None:
    categories = {entry["category"] for entry in hits.values()}

    if any(
        category in {"nopasswd-all", "noauthenticate", "setenv", "all-all"}
        for category in categories
    ) and any(
        category in {
            "temp-exec",
            "user-exec",
            "hidden-exec",
            "ld-hijack",
            "path-hijack",
            "download-exec",
            "reverse-shell",
            "decode-exec",
        }
        for category in categories
    ):
        _record_hit(
            hits,
            reason="sudoers privilege delegation is combined with suspicious execution behavior",
            score=35,
            preview=None,
            category="compound-priv-exec",
        )

    if "cmnd-alias" in categories and any(
        category in {
            "cmnd-alias-temp",
            "cmnd-alias-user",
            "cmnd-alias-hidden",
            "cmnd-alias-download",
            "cmnd-alias-download-exec",
        }
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Cmnd_Alias is paired with high-risk execution indicators",
            score=30,
            preview=None,
            category="compound-cmnd-alias",
        )

    if any(
        category.startswith("include-") for category in categories
    ) and any(
        category in {
            "temp-exec",
            "user-exec",
            "hidden-exec",
            "ld-hijack",
            "path-hijack",
        }
        for category in categories
    ):
        _record_hit(
            hits,
            reason="sudoers include chain is combined with suspicious execution behavior",
            score=25,
            preview=None,
            category="compound-include-exec",
        )

    if any(
        category in {"defaults-env-keep-ld", "defaults-env-keep-path", "secure-path-temp", "secure-path-user", "secure-path-hidden"}
        for category in categories
    ) and any(
        category in {"ld-hijack", "path-hijack", "setenv"}
        for category in categories
    ):
        _record_hit(
            hits,
            reason="sudoers environment handling is combined with hijack-prone execution controls",
            score=30,
            preview=None,
            category="compound-env-hijack",
        )


def _finalize_finding(path: Path, hits: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    high_confidence_categories = {
        "temp-target",
        "user-target",
        "hidden-target",
        "binary",
        "nopasswd-all",
        "noauthenticate",
        "setenv",
        "include-include-temp",
        "include-include-user",
        "include-include-hidden",
        "include-includedir-temp",
        "include-includedir-user",
        "include-includedir-hidden",
        "defaults-env-keep-ld",
        "secure-path-temp",
        "secure-path-user",
        "secure-path-hidden",
        "cmnd-alias-temp",
        "cmnd-alias-user",
        "cmnd-alias-hidden",
        "cmnd-alias-download",
        "cmnd-alias-download-exec",
        "temp-exec",
        "user-exec",
        "hidden-exec",
        "ld-hijack",
        "path-hijack",
        "download-exec",
        "reverse-shell",
        "decode-exec",
        "stealth-privilege",
        "compound-priv-exec",
        "compound-cmnd-alias",
        "compound-include-exec",
        "compound-env-hijack",
    }

    low_signal_only_categories = {
        "download",
        "download-to-risk-path",
        "encoded",
        "one-liner",
        "all-all",
        "nopasswd",
        "defaults-env-keep",
        "defaults-env-check",
        "secure-path",
        "cmnd-alias",
        "include-include",
        "include-includedir",
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
    line_lower = line.strip().lower()
    return any(line_lower.startswith(prefix) for prefix in SUDOERS_METADATA_PREFIXES)


def _severity(score: int) -> str:
    return severity_from_score(score)
