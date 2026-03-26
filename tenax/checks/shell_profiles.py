from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from tenax.checks.common import (
    build_collect_record as shared_build_collect_record,
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

SHELL_PROFILE_PATHS = [
    Path("/etc/profile"),
    Path("/etc/bash.bashrc"),
    Path("/etc/zsh/zshrc"),
    Path("/etc/zshrc"),
    Path("/etc/profile.d"),
    Path("/etc/skel/.bashrc"),
    Path("/etc/skel/.profile"),
    Path("/etc/skel/.zshrc"),
    Path.home() / ".bashrc",
    Path.home() / ".bash_profile",
    Path.home() / ".profile",
    Path.home() / ".zprofile",
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

PATH_HIJACK_REGEX = re.compile(
    r"\bPATH\s*=\s*['\"]?([^'\"\n]+)",
    re.IGNORECASE,
)

LD_HIJACK_REGEX = re.compile(
    r"\b(LD_PRELOAD|LD_LIBRARY_PATH)\s*=\s*['\"]?([^'\"\s]+)",
    re.IGNORECASE,
)

DIRECT_EXEC_REGEX = re.compile(
    r"""
    \b(
        sh|bash|dash|ash|ksh|zsh|
        python|python2|python3|perl|ruby|php|
        exec|source|\.
    )\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

SUSPICIOUS_FILE_EXT_REGEX = re.compile(
    r"\.(sh|py|pl|rb|php|elf|bin|out|so)$",
    re.IGNORECASE,
)

PROMPT_COMMAND_REGEX = re.compile(r"\bPROMPT_COMMAND\s*=", re.IGNORECASE)
TRAP_DEBUG_REGEX = re.compile(r"\btrap\b.*\b(DEBUG|RETURN|EXIT)\b", re.IGNORECASE)
BASH_ENV_REGEX = re.compile(r"\b(BASH_ENV|ENV|PYTHONSTARTUP)\s*=\s*['\"]?([^'\"\s]+)", re.IGNORECASE)
ALIASED_SYSTEM_BINARY_REGEX = re.compile(
    r"""
    ^
    \s*alias\s+
    (sudo|ssh|scp|sftp|ls|cat|vim|vi|nano|python|python3|bash|sh)
    =
    """,
    re.IGNORECASE | re.VERBOSE,
)

COMMON_HARMLESS_EXPORTS = (
    "lang=",
    "term=",
    "editor=",
    "pager=",
    "historysize=",
    "histsize=",
    "histfilesize=",
)


def analyze_shell_profile_locations() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in SHELL_PROFILE_PATHS:
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


def collect_shell_profile_locations(hash_files: bool = False) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in SHELL_PROFILE_PATHS:
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
            reason="Shell profile symlink points to a temporary path",
            score=95,
            preview=f"symlink -> {target_str}",
            category="temp-target",
        )

    if USER_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="Shell profile symlink points to a user-controlled path",
            score=90,
            preview=f"symlink -> {target_str}",
            category="user-target",
        )

    if HIDDEN_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="Shell profile symlink points to a hidden path",
            score=80,
            preview=f"symlink -> {target_str}",
            category="hidden-target",
        )

    stat_info = _safe_lstat(path)
    if stat_info and stat_info.st_uid != 0:
        _record_hit(
            hits,
            reason="Shell profile symlink is owned by a non-root account",
            score=75,
            preview=f"owner={_owner_from_uid(stat_info.st_uid)}",
            category="ownership",
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
                reason="Shell profile is world-writable",
                score=100,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )

    try:
        raw = path.read_bytes()
    except Exception:
        return None

    if b"\x00" in raw[:4096]:
        return None

    try:
        content = raw.decode("utf-8", errors="ignore")
    except Exception:
        return None

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        line_lower = stripped.lower()

        if _is_harmless_export(stripped, line_lower):
            continue

        _detect_exec_behavior(hits, stripped, line_lower, line_number)
        _detect_profile_variable_abuse(hits, stripped, line_lower, line_number)
        _detect_prompt_or_trap_abuse(hits, stripped, line_lower, line_number)
        _detect_alias_hijack(hits, stripped, line_lower, line_number)
        _detect_path_hijack(hits, stripped, line_number)
        _detect_ld_hijack(hits, stripped, line_number)
        _detect_inline_payload_behaviors(hits, stripped, line_lower, line_number)
        _detect_reverse_shells(hits, stripped, line_number)
        _detect_encoded_execution(hits, stripped, line_number)
        _detect_stealth_or_privilege_changes(hits, stripped, line_lower, line_number)

    _apply_compound_behavior_bonuses(hits)

    return _finalize_finding(path, hits)

def _detect_exec_behavior(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    if not DIRECT_EXEC_REGEX.search(line):
        return

    if any(x in line_lower for x in [
        "/tmp/", "/dev/shm/",
        "curl", "wget", "nc", "bash -c"
    ]):
        _record_hit(
            hits,
            reason="Shell profile executes suspicious command",
            score=80,
            preview=_with_line_number(line_number, line),
            category="temp-exec",
        )


def _detect_profile_variable_abuse(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    match = BASH_ENV_REGEX.search(line)
    if not match:
        return

    variable_value = match.group(2)

    if _path_startswith_any(variable_value.lower(), TEMP_PATH_PATTERNS):
        _record_hit(
            hits,
            reason="Shell profile sets variable to temp path",
            score=95,
            preview=_with_line_number(line_number, line),
            category="profile-var-temp",
        )
    elif USER_PATH_REGEX.search(variable_value):
        _record_hit(
            hits,
            reason="Shell profile sets variable to user path",
            score=90,
            preview=_with_line_number(line_number, line),
            category="profile-var-user",
        )
    elif HIDDEN_PATH_REGEX.search(variable_value):
        _record_hit(
            hits,
            reason="Shell profile sets variable to hidden path",
            score=85,
            preview=_with_line_number(line_number, line),
            category="profile-var-hidden",
        )


def _detect_prompt_or_trap_abuse(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    if PROMPT_COMMAND_REGEX.search(line):
        if any(x in line_lower for x in [
            "/tmp/", "/dev/shm/",
            "curl", "wget", "nc"
        ]):
            _record_hit(
                hits,
                reason="Shell profile uses PROMPT_COMMAND with suspicious behavior",
                score=85,
                preview=_with_line_number(line_number, line),
                category="prompt-command",
            )

    if TRAP_DEBUG_REGEX.search(line):
        if any(x in line_lower for x in [
            "/tmp/", "/dev/shm/",
            "curl", "wget", "nc"
        ]):
            _record_hit(
                hits,
                reason="Shell profile defines trap with suspicious behavior",
                score=80,
                preview=_with_line_number(line_number, line),
                category="trap-hook",
            )


def _detect_alias_hijack(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    if not ALIASED_SYSTEM_BINARY_REGEX.match(line):
        return

    if any(x in line_lower for x in [
        "/tmp/", "/dev/shm/",
        "curl", "wget", "nc"
    ]):
        _record_hit(
            hits,
            reason="Shell profile aliases system binary to suspicious command",
            score=85,
            preview=_with_line_number(line_number, line),
            category="alias-hijack",
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

    if path_value == "/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin":
        return

    if any(x in path_value for x in ["/tmp", "/dev/shm"]):
        _record_hit(
            hits,
            reason="Shell profile modifies PATH to include temp directory",
            score=85,
            preview=_with_line_number(line_number, line),
            category="path-hijack",
        )


def _detect_ld_hijack(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    match = LD_HIJACK_REGEX.search(line)
    if not match:
        return

    variable_value = match.group(2)

    if _path_startswith_any(variable_value.lower(), TEMP_PATH_PATTERNS):
        _record_hit(
            hits,
            reason="Shell profile sets LD variable to temp path",
            score=95,
            preview=_with_line_number(line_number, line),
            category="ld-hijack",
        )
    elif USER_PATH_REGEX.search(variable_value):
        _record_hit(
            hits,
            reason="Shell profile sets LD variable to user path",
            score=90,
            preview=_with_line_number(line_number, line),
            category="ld-hijack",
        )
    elif HIDDEN_PATH_REGEX.search(variable_value):
        _record_hit(
            hits,
            reason="Shell profile sets LD variable to hidden path",
            score=85,
            preview=_with_line_number(line_number, line),
            category="ld-hijack",
        )


def _detect_inline_payload_behaviors(
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
            reason="Shell profile downloads content from a remote URL",
            score=60,
            preview=_with_line_number(line_number, line),
            category="download",
        )

    if PIPE_TO_INTERPRETER_REGEX.search(line):
        _record_hit(
            hits,
            reason="Shell profile downloads and executes payload inline",
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
                reason="Shell profile contains a high-risk interpreter one-liner",
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
                reason="Shell profile contains reverse-shell or socket-based execution behavior",
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
            reason="Shell profile decodes content and immediately executes it",
            score=95,
            preview=_with_line_number(line_number, line),
            category="decode-exec",
        )
        return

    for regex in ENCODED_EXEC_REGEXES:
        if regex.search(line):
            _record_hit(
                hits,
                reason="Shell profile contains encoded payload handling logic",
                score=45,
                preview=_with_line_number(line_number, line),
                category="encoded",
            )
            break


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
                reason="Shell profile contains stealth or privilege-manipulation logic",
                score=85,
                preview=_with_line_number(line_number, line),
                category="stealth-privilege",
            )
            return
def _apply_compound_behavior_bonuses(hits: dict[str, dict[str, Any]]) -> None:
    categories = {entry["category"] for entry in hits.values()}

    if any("download" in category for category in categories) and any(
        category in {"download-exec", "reverse-shell", "one-liner", "decode-exec"}
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Shell profile combines download behavior with active execution logic",
            score=35,
            preview=None,
            category="compound-download-exec",
        )

    if "path-hijack" in categories and any(
        category in {
            "temp-exec",
            "user-exec",
            "hidden-exec",
            "ld-hijack",
            "alias-hijack",
            "profile-var-temp",
            "profile-var-user",
            "profile-var-hidden",
        }
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Shell profile combines PATH hijacking with suspicious execution behavior",
            score=25,
            preview=None,
            category="compound-path-hijack",
        )

    if any(
        category in {"prompt-command", "trap-hook", "alias-hijack"}
        for category in categories
    ) and any(
        category in {
            "temp-exec",
            "user-exec",
            "hidden-exec",
            "download-exec",
            "reverse-shell",
            "decode-exec",
        }
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Shell profile combines shell hook abuse with high-risk execution behavior",
            score=30,
            preview=None,
            category="compound-hook-exec",
        )

    if any(
        category in {"profile-var-temp", "profile-var-user", "profile-var-hidden"}
        for category in categories
    ) and any(
        category in {"ld-hijack", "temp-exec", "user-exec", "hidden-exec"}
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Shell profile combines environment variable abuse with suspicious execution behavior",
            score=30,
            preview=None,
            category="compound-env-exec",
        )


def _finalize_finding(path: Path, hits: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    if not hits:
        return None

    categories = {entry["category"] for entry in hits.values()}
    score = sum(int(entry["score"]) for entry in hits.values())

    if not any(cat in categories for cat in {
        "temp-exec",
        "profile-var-temp",
        "profile-var-user",
        "profile-var-hidden",
        "prompt-command",
        "trap-hook",
        "alias-hijack",
        "path-hijack",
        "ld-hijack",
        "download-exec",
        "reverse-shell",
        "decode-exec",
    }):
        return None

    return shared_finalize_finding(path, hits, high_confidence_categories={
        "temp-exec",
        "profile-var-temp",
        "profile-var-user",
        "profile-var-hidden",
        "prompt-command",
        "trap-hook",
        "alias-hijack",
        "path-hijack",
        "ld-hijack",
        "download-exec",
        "reverse-shell",
        "decode-exec",
    })


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
    if any(token in line_lower for token in TEMP_PATH_PATTERNS):
        return True
    return bool(USER_PATH_REGEX.search(line_lower))


def _with_line_number(line_number: int, line: str) -> str:
    return shared_with_line_number(line_number, line)


def _is_harmless_export(line: str, line_lower: str) -> bool:
    if not line_lower.startswith("export "):
        return False
    return any(token in line_lower for token in COMMON_HARMLESS_EXPORTS)


def _severity(score: int) -> str:
    return severity_from_score(score)
