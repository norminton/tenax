from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from tenax.checks.common import build_collect_record, path_startswith_any, record_hit, safe_stat, severity_from_score, with_line_number
from tenax.utils import is_file_safe, path_exists

ENVIRONMENT_HOOK_PATHS = [
    Path("/etc/profile"),
    Path("/etc/environment"),
    Path("/etc/bash.bashrc"),
    Path("/etc/profile.d"),
    Path("/etc/zsh/zshrc"),
    Path("/etc/zshrc"),
    Path.home() / ".bashrc",
    Path.home() / ".bash_profile",
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
]

ENCODED_EXEC_REGEXES = [
    re.compile(r"\bbase64\b.*(-d|--decode)", re.IGNORECASE),
]

ENCODED_TO_EXEC_REGEX = re.compile(
    r"""
    \bbase64\b.*(-d|--decode)
    .*?
    (\||;\s*)
    .*?
    \b(sh|bash|python|perl|php)\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

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
        sh|bash|python|perl|php|
        exec
    )\b
    """,
    re.IGNORECASE | re.VERBOSE,
)


def analyze_environment_hook_locations() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in ENVIRONMENT_HOOK_PATHS:
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


def collect_environment_hook_locations(hash_files: bool = False) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in ENVIRONMENT_HOOK_PATHS:
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
                artifacts.append(build_collect_record(child, hash_files=hash_files))
        else:
            base_str = str(base)
            if base_str in seen_paths:
                continue
            seen_paths.add(base_str)

            if is_file_safe(base):
                artifacts.append(build_collect_record(base, hash_files=hash_files))

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

    if path_startswith_any(target_str, TEMP_PATH_PATTERNS):
        record_hit(
            hits,
            reason="Environment hook symlink points to a temporary path",
            score=95,
            preview=f"symlink -> {target_str}",
            category="temp-target",
        )

    if USER_PATH_REGEX.search(target_str):
        record_hit(
            hits,
            reason="Environment hook symlink points to a user-controlled path",
            score=90,
            preview=f"symlink -> {target_str}",
            category="user-target",
        )

    if HIDDEN_PATH_REGEX.search(target_str):
        record_hit(
            hits,
            reason="Environment hook symlink points to a hidden path",
            score=80,
            preview=f"symlink -> {target_str}",
            category="hidden-target",
        )

    return _finalize_finding(path, hits)


def _analyze_file(path: Path) -> dict[str, Any] | None:
    hits: dict[str, dict[str, Any]] = {}

    stat_info = safe_stat(path)
    if stat_info:
        mode = stat_info.st_mode & 0o777

        if mode & 0o002:
            record_hit(
                hits,
                reason="Environment hook is world-writable",
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

        line_lower = stripped.lower()

        _detect_exec_behavior(hits, stripped, line_lower, line_number)
        _detect_env_variable_abuse(hits, stripped, line_lower, line_number)
        _detect_path_hijack(hits, stripped, line_number)
        _detect_ld_hijack(hits, stripped, line_number)
        _detect_inline_payloads(hits, stripped, line_lower, line_number)
        _detect_reverse_shells(hits, stripped, line_number)
        _detect_encoded_exec(hits, stripped, line_number)

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
        record_hit(
            hits,
            reason="Environment hook executes suspicious command",
            score=80,
            preview=with_line_number(line_number, line),
            category="temp-exec",
        )


def _detect_env_variable_abuse(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    suspicious_vars = (
        "PROMPT_COMMAND=",
        "BASH_ENV=",
        "ENV=",
        "PYTHONSTARTUP=",
        "LD_PRELOAD=",
        "LD_LIBRARY_PATH=",
    )

    if not any(var.lower() in line_lower for var in suspicious_vars):
        return

    if path_startswith_any(line_lower, TEMP_PATH_PATTERNS):
        record_hit(
            hits,
            reason="Environment hook defines sensitive variable using temp path",
            score=95,
            preview=with_line_number(line_number, line),
            category="env-temp",
        )
    elif USER_PATH_REGEX.search(line):
        record_hit(
            hits,
            reason="Environment hook defines sensitive variable using user path",
            score=90,
            preview=with_line_number(line_number, line),
            category="env-user",
        )
    elif HIDDEN_PATH_REGEX.search(line):
        record_hit(
            hits,
            reason="Environment hook defines sensitive variable using hidden path",
            score=85,
            preview=with_line_number(line_number, line),
            category="env-hidden",
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
        record_hit(
            hits,
            reason="Environment hook modifies PATH to include temp directory",
            score=85,
            preview=with_line_number(line_number, line),
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

    if path_startswith_any(variable_value, TEMP_PATH_PATTERNS):
        record_hit(
            hits,
            reason="Environment hook sets LD variable to temp path",
            score=95,
            preview=with_line_number(line_number, line),
            category="ld-hijack",
        )
    elif USER_PATH_REGEX.search(variable_value):
        record_hit(
            hits,
            reason="Environment hook sets LD variable to user path",
            score=90,
            preview=with_line_number(line_number, line),
            category="ld-hijack",
        )
    elif HIDDEN_PATH_REGEX.search(variable_value):
        record_hit(
            hits,
            reason="Environment hook sets LD variable to hidden path",
            score=85,
            preview=with_line_number(line_number, line),
            category="ld-hijack",
        )


def _detect_inline_payloads(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    has_download_tool = bool(DOWNLOAD_TOOL_REGEX.search(line))
    has_url = bool(URL_REGEX.search(line))

    if has_download_tool and has_url:
        record_hit(
            hits,
            reason="Environment hook downloads content from a remote URL",
            score=60,
            preview=with_line_number(line_number, line),
            category="download",
        )

    if PIPE_TO_INTERPRETER_REGEX.search(line):
        record_hit(
            hits,
            reason="Environment hook downloads and executes payload inline",
            score=100,
            preview=with_line_number(line_number, line),
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
            record_hit(
                hits,
                reason="Environment hook contains a high-risk interpreter one-liner",
                score=70,
                preview=with_line_number(line_number, line),
                category="one-liner",
            )


def _detect_reverse_shells(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    for regex in SOCKET_IMPLANT_REGEXES:
        if regex.search(line):
            record_hit(
                hits,
                reason="Environment hook contains reverse-shell or socket-based execution behavior",
                score=100,
                preview=with_line_number(line_number, line),
                category="reverse-shell",
            )
            break


def _detect_encoded_exec(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    if ENCODED_TO_EXEC_REGEX.search(line):
        record_hit(
            hits,
            reason="Environment hook decodes content and immediately executes it",
            score=95,
            preview=with_line_number(line_number, line),
            category="decode-exec",
        )
        return

    for regex in ENCODED_EXEC_REGEXES:
        if regex.search(line):
            record_hit(
                hits,
                reason="Environment hook contains encoded payload handling logic",
                score=45,
                preview=with_line_number(line_number, line),
                category="encoded",
            )
            break


def _apply_compound_behavior_bonuses(hits: dict[str, dict[str, Any]]) -> None:
    categories = {entry["category"] for entry in hits.values()}

    if any("download" in category for category in categories) and any(
        category in {"download-exec", "reverse-shell", "one-liner", "decode-exec"}
        for category in categories
    ):
        record_hit(
            hits,
            reason="Environment hook combines download behavior with active execution logic",
            score=35,
            preview=None,
            category="compound-download-exec",
        )

    if "path-hijack" in categories and any(
        category in {"temp-exec", "user-exec", "hidden-exec", "ld-hijack"}
        for category in categories
    ):
        record_hit(
            hits,
            reason="Environment hook combines PATH hijacking with suspicious execution behavior",
            score=25,
            preview=None,
            category="compound-path-hijack",
        )

    if any(category in {"env-temp", "env-user", "env-hidden"} for category in categories) and any(
        category in {"temp-exec", "user-exec", "hidden-exec", "ld-hijack"}
        for category in categories
    ):
        record_hit(
            hits,
            reason="Environment hook combines sensitive variable abuse with suspicious execution behavior",
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
        "env-temp",
        "env-user",
        "env-hidden",
        "path-hijack",
        "ld-hijack",
        "download-exec",
        "reverse-shell",
        "decode-exec",
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
        "severity": severity_from_score(score),
        "reason": primary_reason,
        "reasons": [entry["reason"] for entry in hits.values()],
        "preview": preview,
    }
