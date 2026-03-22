from __future__ import annotations

import hashlib
import os
import pwd
import re
from pathlib import Path
from typing import Any

from tenax.utils import is_file_safe, path_exists

RC_PATHS = [
    Path("/etc/rc.local"),
    Path("/etc/init.d"),
    Path("/etc/rc0.d"),
    Path("/etc/rc1.d"),
    Path("/etc/rc2.d"),
    Path("/etc/rc3.d"),
    Path("/etc/rc4.d"),
    Path("/etc/rc5.d"),
    Path("/etc/rc6.d"),
]

STANDARD_INIT_TARGET_PREFIXES = (
    "/etc/init.d/",
    "/lib/init/",
    "/usr/lib/",
    "/lib/systemd/",
    "/usr/lib/systemd/",
)

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
    re.compile(r"\bsetcap\b\b", re.IGNORECASE),
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

TEMP_EXEC_REGEXES = [
    re.compile(
        r"""
        \b(
            exec|
            sh|bash|dash|ash|ksh|zsh|
            python|python2|python3|perl|ruby|php|
            nohup|setsid|
            start-stop-daemon|daemon|
            su|runuser
        )\b
        [^\n#;|]*?
        (
            /tmp/|/var/tmp/|/dev/shm/|/run/shm/|
            /home/[^/\s]+/|/root/\.
        )
        """,
        re.IGNORECASE | re.VERBOSE,
    ),
    re.compile(
        r"""
        \b(DAEMON|CMD|COMMAND|EXEC|PROGRAM|PROG)\s*=\s*['"]?
        (
            /tmp/|/var/tmp/|/dev/shm/|/run/shm/|
            /home/[^/\s]+/|/root/\.
        )
        """,
        re.IGNORECASE | re.VERBOSE,
    ),
]

HIDDEN_PATH_EXEC_REGEX = re.compile(
    r"""
    (
        /tmp/|/var/tmp/|/dev/shm/|/run/shm/|
        /home/[^/\s]+/|/root/
    )
    \.[^/\s'"]+
    """,
    re.IGNORECASE | re.VERBOSE,
)

KERNEL_MODULE_TEMP_REGEX = re.compile(
    r"\b(insmod|modprobe)\b[^\n#;|]*(/tmp/|/var/tmp/|/dev/shm/|/run/shm/)",
    re.IGNORECASE,
)

SUSPICIOUS_PROCESS_CONTROL_REGEXES = [
    re.compile(r"\bnohup\b", re.IGNORECASE),
    re.compile(r"\bsetsid\b", re.IGNORECASE),
    re.compile(r"\bdisown\b", re.IGNORECASE),
]

SHEBANG_REGEX = re.compile(
    r"^#!\s*(/bin/sh|/bin/bash|/usr/bin/sh|/usr/bin/bash|/bin/dash|/usr/bin/dash)(\s|$)",
    re.IGNORECASE,
)

START_STOP_DAEMON_SAFE_REGEX = re.compile(
    r"\bstart-stop-daemon\b.*\b(--start|--stop|--exec)\b",
    re.IGNORECASE,
)

START_STOP_DAEMON_EXEC_REGEX = re.compile(
    r"""
    \bstart-stop-daemon\b
    .*?
    (?:
        --exec\s+(['"]?)([^'" \t;|]+)\1 |
        --startas\s+(['"]?)([^'" \t;|]+)\3
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

DIRECT_EXEC_ASSIGNMENT_REGEX = re.compile(
    r"""
    \b(DAEMON|CMD|COMMAND|EXEC|PROGRAM|PROG)\s*=\s*['"]?
    ([^'"\s;|]+)
    """,
    re.IGNORECASE | re.VERBOSE,
)


def analyze_rc_init_locations() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in RC_PATHS:
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


def collect_rc_init_locations(hash_files: bool = False) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in RC_PATHS:
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
            reason="RC symlink target points into a temporary execution path",
            score=95,
            preview=f"symlink -> {target_str}",
            category="temp-target",
        )

    if USER_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="RC symlink target points into a user-controlled path",
            score=90,
            preview=f"symlink -> {target_str}",
            category="user-target",
        )

    if HIDDEN_PATH_EXEC_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="RC symlink target references a hidden path",
            score=75,
            preview=f"symlink -> {target_str}",
            category="hidden-target",
        )

    if target_str and not target_str.startswith(STANDARD_INIT_TARGET_PREFIXES):
        if _path_startswith_any(target_str, TEMP_PATH_PATTERNS) or USER_PATH_REGEX.search(target_str):
            _record_hit(
                hits,
                reason="RC symlink target is outside standard init locations and in a high-risk path",
                score=85,
                preview=f"symlink -> {target_str}",
                category="nonstandard-target",
            )

    stat_info = _safe_lstat(path)
    if stat_info and stat_info.st_uid != 0:
        owner_name = _owner_from_uid(stat_info.st_uid)
        _record_hit(
            hits,
            reason="RC symlink is owned by a non-root account",
            score=70,
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
                reason="Init artifact is owned by a non-root account",
                score=80,
                preview=f"owner={owner_name}",
                category="ownership",
            )

        if mode & 0o002:
            _record_hit(
                hits,
                reason="Init artifact is world-writable",
                score=95,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )
        elif mode & 0o020:
            _record_hit(
                hits,
                reason="Init artifact is group-writable",
                score=55,
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
            reason="Init artifact contains binary content instead of a normal shell script",
            score=70,
            preview="[binary content omitted]",
            category="binary",
        )
        return _finalize_finding(path, hits)

    try:
        content = raw.decode("utf-8", errors="ignore")
    except Exception:
        return _finalize_finding(path, hits)

    shebang_seen = False

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue

        line_lower = stripped.lower()

        # Keep the shebang as context only. Do not score it.
        if not shebang_seen and SHEBANG_REGEX.search(stripped):
            shebang_seen = True

        comment_only = stripped.startswith("#") and not stripped.startswith("#!")
        if comment_only:
            continue

        _detect_network_retrieval(hits, stripped, line_lower, line_number)
        _detect_pipe_to_interpreter(hits, stripped, line_number)
        _detect_interpreter_one_liners(hits, stripped, line_number)
        _detect_reverse_shells(hits, stripped, line_number)
        _detect_encoded_execution(hits, stripped, line_number)
        _detect_temp_or_user_exec(hits, stripped, line_lower, line_number)
        _detect_ld_hijack(hits, stripped, line_number)
        _detect_path_hijack(hits, stripped, line_number)
        _detect_kernel_module_from_temp(hits, stripped, line_number)
        _detect_stealth_or_privilege_changes(hits, stripped, line_number)
        _detect_process_detach(hits, stripped, line_number)

    _apply_compound_behavior_bonuses(hits)

    return _finalize_finding(path, hits)


def _detect_network_retrieval(
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
            reason="Init artifact downloads content from a remote URL",
            score=55,
            preview=_with_line_number(line_number, line),
            category="download",
        )

    if has_download_tool and any(token in line_lower for token in ("-o ", "--output", "> /", ">> /")):
        if _contains_high_risk_path(line_lower):
            _record_hit(
                hits,
                reason="Init artifact downloads remote content into a high-risk local path",
                score=65,
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
            reason="Init artifact pipes downloader output directly into an interpreter",
            score=95,
            preview=_with_line_number(line_number, line),
            category="download-exec",
        )


def _detect_interpreter_one_liners(
    hits: dict[str, dict[str, Any]],
    line: str,
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
        if any(term in line.lower() for term in high_signal_terms):
            _record_hit(
                hits,
                reason="Init artifact contains a high-risk interpreter one-liner",
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
                reason="Init artifact contains reverse-shell or socket-based execution behavior",
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
            reason="Init artifact decodes content and immediately executes it",
            score=90,
            preview=_with_line_number(line_number, line),
            category="decode-exec",
        )
        return

    for regex in ENCODED_EXEC_REGEXES:
        if regex.search(line):
            _record_hit(
                hits,
                reason="Init artifact contains encoded payload handling logic",
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
    for regex in TEMP_EXEC_REGEXES:
        if regex.search(line):
            if _path_startswith_any(line_lower, TEMP_PATH_PATTERNS):
                _record_hit(
                    hits,
                    reason="Init artifact executes or configures content from a temporary path",
                    score=85,
                    preview=_with_line_number(line_number, line),
                    category="temp-exec",
                )
            elif USER_PATH_REGEX.search(line):
                _record_hit(
                    hits,
                    reason="Init artifact executes or configures content from a user-controlled path",
                    score=80,
                    preview=_with_line_number(line_number, line),
                    category="user-exec",
                )

    if HIDDEN_PATH_EXEC_REGEX.search(line):
        _record_hit(
            hits,
            reason="Init artifact references a hidden executable or payload path",
            score=70,
            preview=_with_line_number(line_number, line),
            category="hidden-path",
        )

    if START_STOP_DAEMON_SAFE_REGEX.search(line):
        daemon_exec_match = START_STOP_DAEMON_EXEC_REGEX.search(line)
        if daemon_exec_match:
            exec_path = (
                daemon_exec_match.group(2)
                or daemon_exec_match.group(4)
                or ""
            ).strip()

            if exec_path:
                exec_path_lower = exec_path.lower()

                if _path_startswith_any(exec_path_lower, TEMP_PATH_PATTERNS):
                    _record_hit(
                        hits,
                        reason="Init artifact uses start-stop-daemon with an executable in a temporary path",
                        score=85,
                        preview=_with_line_number(line_number, line),
                        category="ssd-temp-exec",
                    )
                elif USER_PATH_REGEX.search(exec_path):
                    _record_hit(
                        hits,
                        reason="Init artifact uses start-stop-daemon with an executable in a user-controlled path",
                        score=80,
                        preview=_with_line_number(line_number, line),
                        category="ssd-user-exec",
                    )
                elif HIDDEN_PATH_EXEC_REGEX.search(exec_path):
                    _record_hit(
                        hits,
                        reason="Init artifact uses start-stop-daemon with a hidden executable path",
                        score=75,
                        preview=_with_line_number(line_number, line),
                        category="ssd-hidden-exec",
                    )

    assignment_match = DIRECT_EXEC_ASSIGNMENT_REGEX.search(line)
    if assignment_match:
        assigned_path = assignment_match.group(2).strip()
        assigned_path_lower = assigned_path.lower()

        if _path_startswith_any(assigned_path_lower, TEMP_PATH_PATTERNS):
            _record_hit(
                hits,
                reason="Init artifact assigns a daemon or command path into a temporary directory",
                score=80,
                preview=_with_line_number(line_number, line),
                category="temp-daemon-assignment",
            )
        elif USER_PATH_REGEX.search(assigned_path):
            _record_hit(
                hits,
                reason="Init artifact assigns a daemon or command path into a user-controlled directory",
                score=75,
                preview=_with_line_number(line_number, line),
                category="user-daemon-assignment",
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

    if _contains_high_risk_path(variable_value):
        _record_hit(
            hits,
            reason=f"Init artifact sets {variable_name} to a high-risk library path",
            score=95,
            preview=_with_line_number(line_number, line),
            category="ld-hijack",
        )
    else:
        _record_hit(
            hits,
            reason=f"Init artifact modifies {variable_name}, which can alter library loading behavior",
            score=45,
            preview=_with_line_number(line_number, line),
            category="ld-modification",
        )


def _detect_path_hijack(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    match = PATH_HIJACK_REGEX.search(line)
    if not match:
        return

    path_value = match.group(1).strip().strip("'\"")
    normalized_lower = path_value.lower()

    if not path_value:
        return

    path_segments = path_value.split(":")
    suspicious_segments = []

    for segment in path_segments:
        stripped = segment.strip()
        lowered = stripped.lower()

        if not stripped or stripped == ".":
            suspicious_segments.append(stripped or "<empty>")
            continue

        if _path_startswith_any(lowered, TEMP_PATH_PATTERNS):
            suspicious_segments.append(stripped)
            continue

        if USER_PATH_REGEX.search(stripped):
            suspicious_segments.append(stripped)
            continue

    if suspicious_segments:
        _record_hit(
            hits,
            reason="Init artifact modifies PATH to include risky search-order locations",
            score=70,
            preview=_with_line_number(line_number, line),
            category="path-hijack",
        )
    elif normalized_lower.startswith(".:") or normalized_lower.endswith(":.") or ":.:" in normalized_lower:
        _record_hit(
            hits,
            reason="Init artifact modifies PATH to search the current directory",
            score=65,
            preview=_with_line_number(line_number, line),
            category="path-current-dir",
        )


def _detect_kernel_module_from_temp(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    if KERNEL_MODULE_TEMP_REGEX.search(line):
        _record_hit(
            hits,
            reason="Init artifact loads a kernel module from a temporary path",
            score=100,
            preview=_with_line_number(line_number, line),
            category="kernel-temp",
        )


def _detect_stealth_or_privilege_changes(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    line_lower = line.lower()

    for regex in STEALTH_PERSISTENCE_REGEXES:
        if regex.search(line):
            # Suppress common benign chmod/chown style service housekeeping
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
                reason="Init artifact contains stealth or privilege-manipulation logic",
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
    for regex in SUSPICIOUS_PROCESS_CONTROL_REGEXES:
        if regex.search(line):
            _record_hit(
                hits,
                reason="Init artifact contains detached or hidden process-control behavior",
                score=35,
                preview=_with_line_number(line_number, line),
                category="detach",
            )
            break


def _apply_compound_behavior_bonuses(hits: dict[str, dict[str, Any]]) -> None:
    categories = set(hits.keys())

    if {"download", "download-exec"} <= categories or {"download", "temp-exec"} <= categories:
        _record_hit(
            hits,
            reason="Init artifact combines remote retrieval with direct execution behavior",
            score=40,
            preview=_best_preview_from_hits(hits),
            category="compound-download-exec",
        )

    if {"encoded", "decode-exec"} & categories and (
        {"temp-exec", "user-exec", "reverse-shell"} & categories
    ):
        _record_hit(
            hits,
            reason="Init artifact combines encoded payload handling with execution behavior",
            score=35,
            preview=_best_preview_from_hits(hits),
            category="compound-encoded-exec",
        )

    if {"permissions-world", "permissions-group", "ownership"} & categories and (
        {"temp-exec", "user-exec", "download-exec", "reverse-shell", "ld-hijack"} & categories
    ):
        _record_hit(
            hits,
            reason="Init artifact combines risky file control with suspicious execution behavior",
            score=35,
            preview=_best_preview_from_hits(hits),
            category="compound-control-exec",
        )

    if {"ld-hijack", "path-hijack"} & categories and (
        {"temp-exec", "user-exec", "download-exec"} & categories
    ):
        _record_hit(
            hits,
            reason="Init artifact combines execution-path manipulation with high-risk execution",
            score=35,
            preview=_best_preview_from_hits(hits),
            category="compound-hijack-exec",
        )

    if {"reverse-shell", "download-exec"} <= categories:
        _record_hit(
            hits,
            reason="Init artifact combines remote retrieval with interactive command-channel behavior",
            score=50,
            preview=_best_preview_from_hits(hits),
            category="compound-c2",
        )


def _record_hit(
    hits: dict[str, dict[str, Any]],
    reason: str,
    score: int,
    preview: str,
    category: str,
) -> None:
    existing = hits.get(category)
    if existing is None or score > int(existing.get("score", 0)):
        hits[category] = {
            "reason": reason,
            "score": score,
            "preview": preview,
        }


def _finalize_finding(path: Path, hits: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    if not hits:
        return None

    reasons = [entry["reason"] for entry in hits.values()]
    previews = [entry["preview"] for entry in hits.values() if entry.get("preview")]
    categories = {entry["category"] for entry in hits.values()}
    score = sum(int(entry["score"]) for entry in hits.values())

    high_confidence_categories = {
        "download-exec",
        "reverse-shell",
        "temp-exec",
        "user-exec",
        "decode-exec",
        "ld-hijack",
        "kernel-module-temp",
        "nonstandard-target",
        "temp-target",
        "user-target",
        "hidden-target",
        "binary",
        "ownership",
        "permissions",
    }

    low_signal_only_categories = {
        "shebang",
        "relative-link",
        "process-detach",
    }

    has_high_confidence = bool(categories & high_confidence_categories)
    only_low_signal = categories and categories.issubset(low_signal_only_categories)

    # Suppress weak/noisy findings
    if only_low_signal and score < 80:
        return None

    if not has_high_confidence and score < 90 and len(categories) < 2:
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


def _build_collect_record(path: Path, hash_files: bool = False) -> dict[str, Any]:
    record: dict[str, Any] = {
        "path": str(path),
        "type": "artifact",
        "exists": path.exists() or path.is_symlink(),
        "owner": "unknown",
        "permissions": "unknown",
    }

    stat_info = _safe_lstat(path) if path.is_symlink() else _safe_stat(path)
    if stat_info:
        record["permissions"] = oct(stat_info.st_mode & 0o777)
        record["owner"] = _owner_from_uid(stat_info.st_uid)

    if path.is_symlink():
        record["symlink_target"] = _readlink_safely(path)

    if hash_files and path.exists() and path.is_file() and not path.is_symlink():
        try:
            record["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        except Exception:
            pass

    return record


def _safe_iterdir(path: Path) -> list[Path]:
    try:
        return list(path.iterdir())
    except Exception:
        return []


def _safe_stat(path: Path) -> os.stat_result | None:
    try:
        return path.stat()
    except Exception:
        return None


def _safe_lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except Exception:
        return None


def _owner_from_uid(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def _readlink_safely(path: Path) -> str | None:
    try:
        return os.readlink(path)
    except Exception:
        return None


def _path_startswith_any(value: str, prefixes: tuple[str, ...]) -> bool:
    lowered = value.lower()
    return any(lowered.startswith(prefix.lower()) for prefix in prefixes)


def _contains_high_risk_path(value: str) -> bool:
    lowered = value.lower()
    if _path_startswith_any(lowered, TEMP_PATH_PATTERNS):
        return True
    if any(prefix.lower() in lowered for prefix in TEMP_PATH_PATTERNS):
        return True
    if USER_PATH_REGEX.search(value):
        return True
    return False


def _best_preview_from_hits(hits: dict[str, dict[str, Any]]) -> str:
    if not hits:
        return ""
    best = max(hits.values(), key=lambda item: int(item.get("score", 0)))
    return str(best.get("preview", ""))


def _with_line_number(line_number: int, line: str, max_length: int = 220) -> str:
    flattened = " ".join(line.split())
    if len(flattened) > max_length:
        flattened = flattened[: max_length - 3] + "..."
    return f"L{line_number}: {flattened}"


def _severity(score: int) -> str:
    if score >= 220:
        return "CRITICAL"
    if score >= 120:
        return "HIGH"
    if score >= 60:
        return "MEDIUM"
    if score >= 25:
        return "LOW"
    return "INFO"