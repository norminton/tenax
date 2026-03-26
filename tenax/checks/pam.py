from __future__ import annotations

import os
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

PAM_PATHS = [
    Path("/etc/pam.d"),
]

STANDARD_PAM_MODULE_PREFIXES = (
    "/lib/security/",
    "/lib64/security/",
    "/usr/lib/security/",
    "/usr/lib64/security/",
    "/usr/local/lib/security/",
    "/usr/local/lib64/security/",
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

PAM_EXEC_REGEX = re.compile(
    r"""
    ^
    \s*
    (auth|account|password|session)
    \s+
    (\[[^\]]+\]|\S+)
    \s+
    pam_exec\.so
    (?P<args>.*)
    $
    """,
    re.IGNORECASE | re.VERBOSE,
)

PAM_MODULE_LINE_REGEX = re.compile(
    r"""
    ^
    \s*
    (?P<ptype>auth|account|password|session)
    \s+
    (?P<control>\[[^\]]+\]|\S+)
    \s+
    (?P<module>\S+)
    (?P<args>.*)
    $
    """,
    re.IGNORECASE | re.VERBOSE,
)

PAM_INCLUDE_REGEX = re.compile(
    r"""
    ^
    \s*
    (?P<keyword>include|substack)
    \s+
    (?P<target>\S+)
    \s*$
    """,
    re.IGNORECASE | re.VERBOSE,
)

PAM_PERMIT_REGEX = re.compile(
    r"""
    ^
    \s*
    (?P<ptype>auth|account|password|session)
    \s+
    (?P<control>\[[^\]]+\]|\S+)
    \s+
    pam_permit\.so
    (?P<args>.*)
    $
    """,
    re.IGNORECASE | re.VERBOSE,
)

PAM_DENY_REGEX = re.compile(
    r"""
    ^
    \s*
    (?P<ptype>auth|account|password|session)
    \s+
    (?P<control>\[[^\]]+\]|\S+)
    \s+
    pam_deny\.so
    (?P<args>.*)
    $
    """,
    re.IGNORECASE | re.VERBOSE,
)

PAM_ENV_REGEX = re.compile(
    r"""
    ^
    \s*
    (?P<ptype>auth|account|password|session)
    \s+
    (?P<control>\[[^\]]+\]|\S+)
    \s+
    pam_env\.so
    (?P<args>.*)
    $
    """,
    re.IGNORECASE | re.VERBOSE,
)

MODULE_PATH_REGEX = re.compile(r"(/[^\s]+)")
ENV_FILE_ARG_REGEX = re.compile(r"\b(?:envfile|conffile|user_envfile)\s*=\s*([^\s]+)", re.IGNORECASE)

PAM_PERMIT_COMMON_LEGIT_FILES = {
    "gdm-autologin",
    "gdm-launch-environment",
}

PAM_PERMIT_SESSION_LEGIT_FILES = {
    "common-session",
    "common-session-noninteractive",
}

HIGH_RISK_PAM_MODULES = {
    "pam_exec.so",
    "pam_python.so",
    "pam_script.so",
}


def analyze_pam_locations() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in PAM_PATHS:
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


def collect_pam_locations(hash_files: bool = False) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in PAM_PATHS:
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
            reason="PAM configuration symlink target points into a temporary execution path",
            score=95,
            preview=f"symlink -> {target_str}",
            category="temp-target",
        )

    if USER_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="PAM configuration symlink target points into a user-controlled path",
            score=90,
            preview=f"symlink -> {target_str}",
            category="user-target",
        )

    if HIDDEN_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="PAM configuration symlink target references a hidden path",
            score=75,
            preview=f"symlink -> {target_str}",
            category="hidden-target",
        )

    stat_info = _safe_lstat(path)
    if stat_info and stat_info.st_uid != 0:
        owner_name = _owner_from_uid(stat_info.st_uid)
        _record_hit(
            hits,
            reason="PAM configuration symlink is owned by a non-root account",
            score=75,
            preview=f"owner={owner_name}",
            category="ownership",
        )

    return _finalize_finding(path, hits)


def _analyze_file(path: Path) -> dict[str, Any] | None:
    hits: dict[str, dict[str, Any]] = {}
    basename = path.name.lower()

    stat_info = _safe_stat(path)
    if stat_info:
        mode = stat_info.st_mode & 0o777

        if mode & 0o002:
            _record_hit(
                hits,
                reason="PAM configuration is world-writable",
                score=100,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )
        elif mode & 0o020:
            _record_hit(
                hits,
                reason="PAM configuration is group-writable",
                score=60,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )

    try:
        raw = path.read_bytes()
    except Exception:
        return None

    if b"\x00" in raw[:4096]:
        _record_hit(
            hits,
            reason="PAM configuration contains binary content",
            score=85,
            preview="[binary content omitted]",
            category="binary",
        )
        return _finalize_finding(path, hits)

    try:
        content = raw.decode("utf-8", errors="ignore")
    except Exception:
        return None

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        line_lower = stripped.lower()

        _detect_include_paths(hits, stripped, line_number)
        _detect_module_path_risk(hits, stripped, line_number)
        _detect_pam_exec(hits, stripped, line_lower, line_number)
        _detect_pam_permit(hits, basename, stripped, line_number)
        _detect_pam_env_abuse(hits, stripped, line_lower, line_number)
        _detect_inline_payload_behaviors(hits, stripped, line_lower, line_number)

    _apply_compound_behavior_bonuses(hits)

    return _finalize_finding(path, hits)


def _detect_include_paths(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    include_match = PAM_INCLUDE_REGEX.match(line)
    if not include_match:
        return

    target = include_match.group("target")
    target_lower = target.lower()

    if _path_startswith_any(target_lower, TEMP_PATH_PATTERNS):
        _record_hit(
            hits,
            reason="PAM include or substack references a temporary path",
            score=95,
            preview=_with_line_number(line_number, line),
            category="temp-include",
        )

    if USER_PATH_REGEX.search(target):
        _record_hit(
            hits,
            reason="PAM include or substack references a user-controlled path",
            score=90,
            preview=_with_line_number(line_number, line),
            category="user-include",
        )

    if HIDDEN_PATH_REGEX.search(target):
        _record_hit(
            hits,
            reason="PAM include or substack references a hidden path",
            score=75,
            preview=_with_line_number(line_number, line),
            category="hidden-include",
        )


def _detect_module_path_risk(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    module_match = PAM_MODULE_LINE_REGEX.match(line)
    if not module_match:
        return

    module = module_match.group("module")
    module_lower = module.lower()

    if module_lower in HIGH_RISK_PAM_MODULES:
        if module_lower == "pam_python.so":
            _record_hit(
                hits,
                reason="PAM configuration loads pam_python.so",
                score=70,
                preview=_with_line_number(line_number, line),
                category="pam-python",
            )
        elif module_lower == "pam_script.so":
            _record_hit(
                hits,
                reason="PAM configuration loads pam_script.so",
                score=80,
                preview=_with_line_number(line_number, line),
                category="pam-script",
            )

    if module.startswith("/"):
        if _path_startswith_any(module_lower, TEMP_PATH_PATTERNS):
            _record_hit(
                hits,
                reason="PAM module path points into a temporary directory",
                score=100,
                preview=_with_line_number(line_number, line),
                category="temp-module",
            )
        elif USER_PATH_REGEX.search(module):
            _record_hit(
                hits,
                reason="PAM module path points into a user-controlled location",
                score=95,
                preview=_with_line_number(line_number, line),
                category="user-module",
            )
        elif HIDDEN_PATH_REGEX.search(module):
            _record_hit(
                hits,
                reason="PAM module path references a hidden location",
                score=80,
                preview=_with_line_number(line_number, line),
                category="hidden-module",
            )
        elif not module.startswith(STANDARD_PAM_MODULE_PREFIXES):
            _record_hit(
                hits,
                reason="PAM module path is an absolute path outside standard PAM module directories",
                score=80,
                preview=_with_line_number(line_number, line),
                category="nonstandard-module",
            )


def _detect_pam_exec(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    match = PAM_EXEC_REGEX.match(line)
    if not match:
        return

    args = (match.group("args") or "").strip()
    args_lower = args.lower()

    module_paths = MODULE_PATH_REGEX.findall(args)
    for candidate in module_paths:
        candidate_lower = candidate.lower()

        if _path_startswith_any(candidate_lower, TEMP_PATH_PATTERNS):
            _record_hit(
                hits,
                reason="pam_exec.so references a command path in a temporary directory",
                score=100,
                preview=_with_line_number(line_number, line),
                category="pam-exec-temp-path",
            )
        elif USER_PATH_REGEX.search(candidate):
            _record_hit(
                hits,
                reason="pam_exec.so references a command path in a user-controlled location",
                score=95,
                preview=_with_line_number(line_number, line),
                category="pam-exec-user-path",
            )
        elif HIDDEN_PATH_REGEX.search(candidate):
            _record_hit(
                hits,
                reason="pam_exec.so references a hidden command or payload path",
                score=80,
                preview=_with_line_number(line_number, line),
                category="pam-exec-hidden-path",
            )

    if "expose_authtok" in args_lower:
        _record_hit(
            hits,
            reason="pam_exec.so is configured with expose_authtok",
            score=85,
            preview=_with_line_number(line_number, line),
            category="pam-exec-credential-access",
        )

    _detect_inline_payload_behaviors(hits, line, line_lower, line_number, prefix="pam_exec")


def _detect_pam_permit(
    hits: dict[str, dict[str, Any]],
    basename: str,
    line: str,
    line_number: int,
) -> None:
    match = PAM_PERMIT_REGEX.match(line)
    if not match:
        return

    ptype = match.group("ptype").lower()

    if basename in PAM_PERMIT_COMMON_LEGIT_FILES:
        return

    if ptype == "session" and basename in PAM_PERMIT_SESSION_LEGIT_FILES:
        return

    if ptype in {"auth", "account", "password"}:
        return


def _detect_pam_env_abuse(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    match = PAM_ENV_REGEX.match(line)
    if not match:
        return

    args = (match.group("args") or "").strip()

    if "user_readenv=1" in line_lower:
        _record_hit(
            hits,
            reason="pam_env.so allows user-controlled environment loading",
            score=65,
            preview=_with_line_number(line_number, line),
            category="pam-env-user-readenv",
        )

    for env_match in ENV_FILE_ARG_REGEX.finditer(args):
        env_path = env_match.group(1)
        env_path_lower = env_path.lower()

        if _path_startswith_any(env_path_lower, TEMP_PATH_PATTERNS):
            _record_hit(
                hits,
                reason="pam_env.so references an environment file in a temporary path",
                score=90,
                preview=_with_line_number(line_number, line),
                category="pam-env-temp-file",
            )
        elif USER_PATH_REGEX.search(env_path):
            _record_hit(
                hits,
                reason="pam_env.so references a user-controlled environment file",
                score=85,
                preview=_with_line_number(line_number, line),
                category="pam-env-user-file",
            )
        elif HIDDEN_PATH_REGEX.search(env_path):
            _record_hit(
                hits,
                reason="pam_env.so references a hidden environment file path",
                score=75,
                preview=_with_line_number(line_number, line),
                category="pam-env-hidden-file",
            )


def _detect_inline_payload_behaviors(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
    prefix: str | None = None,
) -> None:
    reason_prefix = ""
    if prefix == "pam_exec":
        reason_prefix = "pam_exec.so command "

    has_download_tool = bool(DOWNLOAD_TOOL_REGEX.search(line))
    has_url = bool(URL_REGEX.search(line))

    if has_download_tool and has_url:
        _record_hit(
            hits,
            reason=f"{reason_prefix}downloads content from a remote URL".strip().capitalize(),
            score=60,
            preview=_with_line_number(line_number, line),
            category=f"{prefix or 'generic'}-download",
        )

    if PIPE_TO_INTERPRETER_REGEX.search(line):
        _record_hit(
            hits,
            reason=f"{reason_prefix}pipes downloaded content directly into an interpreter".strip().capitalize(),
            score=100,
            preview=_with_line_number(line_number, line),
            category=f"{prefix or 'generic'}-download-exec",
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
                reason=f"{reason_prefix}contains a high-risk interpreter one-liner".strip().capitalize(),
                score=70,
                preview=_with_line_number(line_number, line),
                category=f"{prefix or 'generic'}-one-liner",
            )

    for regex in SOCKET_IMPLANT_REGEXES:
        if regex.search(line):
            _record_hit(
                hits,
                reason=f"{reason_prefix}contains reverse-shell or socket-based execution behavior".strip().capitalize(),
                score=100,
                preview=_with_line_number(line_number, line),
                category=f"{prefix or 'generic'}-reverse-shell",
            )
            break

    if ENCODED_TO_EXEC_REGEX.search(line):
        _record_hit(
            hits,
            reason=f"{reason_prefix}decodes content and immediately executes it".strip().capitalize(),
            score=95,
            preview=_with_line_number(line_number, line),
            category=f"{prefix or 'generic'}-decode-exec",
        )
        return

    for regex in ENCODED_EXEC_REGEXES:
        if regex.search(line):
            _record_hit(
                hits,
                reason=f"{reason_prefix}contains encoded payload handling logic".strip().capitalize(),
                score=45,
                preview=_with_line_number(line_number, line),
                category=f"{prefix or 'generic'}-encoded",
            )
            break

    if _contains_high_risk_path(line_lower):
        if any(token in line_lower for token in ("exec", "command", "program", "daemon", "run")):
            _record_hit(
                hits,
                reason=f"{reason_prefix}references a high-risk execution path".strip().capitalize(),
                score=75,
                preview=_with_line_number(line_number, line),
                category=f"{prefix or 'generic'}-risk-path",
            )


def _apply_compound_behavior_bonuses(hits: dict[str, dict[str, Any]]) -> None:
    categories = {entry["category"] for entry in hits.values()}

    if any("download" in category for category in categories) and any(
        category.endswith("reverse-shell") or "one-liner" in category or "decode-exec" in category
        for category in categories
    ):
        _record_hit(
            hits,
            reason="PAM configuration combines download behavior with active execution logic",
            score=35,
            preview=None,
            category="compound-download-exec",
        )

    if "pam-exec" in categories and any(
        category.startswith("pam_exec-") and category != "pam-exec"
        for category in categories
    ):
        _record_hit(
            hits,
            reason="pam_exec.so is combined with additional high-risk execution indicators",
            score=30,
            preview=None,
            category="compound-pam-exec",
        )

    if "pam-env-user-readenv" in categories and any(
        category in {"pam-env-temp-file", "pam-env-user-file", "pam-env-hidden-file"}
        for category in categories
    ):
        _record_hit(
            hits,
            reason="pam_env.so allows user-controlled environment loading from a suspicious path",
            score=35,
            preview=None,
            category="compound-pam-env",
        )


def _finalize_finding(path: Path, hits: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    if not hits:
        return None

    categories = {entry["category"] for entry in hits.values()}
    score = sum(int(entry["score"]) for entry in hits.values())

    if not any(cat in categories for cat in {
        "pam-permit-high-risk",
        "pam-exec-credential-access",
        "pam-exec-temp-path",
        "pam-exec-user-path",
        "pam-exec-hidden-path",
        "pam_exec-download-exec",
        "pam_exec-reverse-shell",
        "pam_exec-decode-exec",
        "temp-module",
        "user-module",
        "hidden-module",
        "temp-include",
        "user-include",
        "hidden-include",
        "pam-env-temp-file",
        "pam-env-user-file",
        "pam-env-hidden-file",
    }):
        return None

    return shared_finalize_finding(path, hits, high_confidence_categories={
        "pam-permit-high-risk",
        "pam-exec-credential-access",
        "pam-exec-temp-path",
        "pam-exec-user-path",
        "pam-exec-hidden-path",
        "pam_exec-download-exec",
        "pam_exec-reverse-shell",
        "pam_exec-decode-exec",
        "temp-module",
        "user-module",
        "hidden-module",
        "temp-include",
        "user-include",
        "hidden-include",
        "pam-env-temp-file",
        "pam-env-user-file",
        "pam-env-hidden-file",
    }, mode="expanded")


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


def _severity(score: int) -> str:
    return severity_from_score(score)
