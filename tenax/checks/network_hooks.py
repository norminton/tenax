from __future__ import annotations

import hashlib
import pwd
import re
from pathlib import Path
from typing import Any

from tenax.utils import is_file_safe, path_exists

DEFAULT_PATH = "/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin"

NETWORK_HOOK_PATHS = [
    Path("/etc/NetworkManager"),
    Path("/etc/network"),
    Path("/etc/netplan"),
    Path("/etc/systemd/network"),
    Path("/etc/ppp"),
    Path("/etc/resolv.conf"),
    Path("/etc/hosts"),
    Path("/etc/hostname"),
    Path("/usr/lib/NetworkManager"),
    Path("/usr/lib/systemd/network"),
    Path("/lib/systemd/network"),
    Path.home() / ".config/NetworkManager",
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

EXEC_HOOK_KEYS = re.compile(
    r"""
    ^
    \s*
    (
        ExecStart|ExecStartPre|ExecStartPost|
        ExecStop|ExecStopPost|
        pre-up|up|post-up|down|post-down|
        dispatcher-script|script|command|run
    )
    \s*[:=]?\s*(.+)
    $
    """,
    re.IGNORECASE | re.VERBOSE,
)

DNS_KEY_REGEX = re.compile(
    r"""
    ^
    \s*
    (
        dns|dns-search|dns-options|
        nameserver|search|domain|
        DNS|FallbackDNS
    )
    \s*[:=]?\s*(.+)
    $
    """,
    re.IGNORECASE | re.VERBOSE,
)

ROUTE_HOOK_REGEX = re.compile(
    r"""
    ^
    \s*
    (
        post-up|pre-up|up|down|post-down|
        routing-policy|routes
    )
    \s*[:=]?\s*(.+)
    $
    """,
    re.IGNORECASE | re.VERBOSE,
)

PROXY_REGEX = re.compile(
    r"\b(proxy|http_proxy|https_proxy|ftp_proxy|all_proxy|socks5h?://)\b",
    re.IGNORECASE,
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

SYSTEM_HOSTS_PATHS = {
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/hostname",
}


def analyze_network_hook_locations() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in NETWORK_HOOK_PATHS:
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


def collect_network_hook_locations(hash_files: bool = False) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in NETWORK_HOOK_PATHS:
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
            reason="Network hook symlink points to a temporary path",
            score=95,
            preview=f"symlink -> {target_str}",
            category="temp-target",
        )

    if USER_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="Network hook symlink points to a user-controlled path",
            score=90,
            preview=f"symlink -> {target_str}",
            category="user-target",
        )

    if HIDDEN_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="Network hook symlink points to a hidden path",
            score=80,
            preview=f"symlink -> {target_str}",
            category="hidden-target",
        )

    stat_info = _safe_lstat(path)
    if stat_info and stat_info.st_uid != 0:
        _record_hit(
            hits,
            reason="Network hook symlink is owned by a non-root account",
            score=75,
            preview=f"owner={_owner_from_uid(stat_info.st_uid)}",
            category="ownership",
        )

    return _finalize_finding(path, hits)


def _analyze_file(path: Path) -> dict[str, Any] | None:
    hits: dict[str, dict[str, Any]] = {}
    path_str = str(path)
    path_lower = path_str.lower()

    stat_info = _safe_stat(path)
    if stat_info:
        mode = stat_info.st_mode & 0o777

        # 🔥 CHANGED: defer ownership instead of immediate flag
        if stat_info.st_uid != 0:
            hits["_ownership_flag"] = {"uid": stat_info.st_uid}

        if mode & 0o002:
            _record_hit(
                hits,
                reason="Network hook file is world-writable",
                score=100,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )
        elif mode & 0o020:
            _record_hit(
                hits,
                reason="Network hook file is group-writable",
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
            reason="Network hook file contains binary content instead of expected text configuration",
            score=75,
            preview="[binary content omitted]",
            category="binary",
        )
        return _finalize_finding(path, hits)

    try:
        content = raw.decode("utf-8", errors="ignore")
    except Exception:
        return _finalize_finding(path, hits)

    # 🔥 OPTIONAL NOISE REDUCTION (PPP defaults)
    if len(content.splitlines()) < 5 and "ppp" in path_str:
        return None

    if path_str in SYSTEM_HOSTS_PATHS:
        _detect_core_network_file_risk(hits, path, content)

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        line_lower = stripped.lower()

        _detect_exec_hooks(hits, stripped, line_lower, line_number)
        _detect_dns_abuse(hits, stripped, line_lower, line_number)
        _detect_route_or_policy_hooks(hits, stripped, line_lower, line_number)
        _detect_proxy_abuse(hits, stripped, line_lower, line_number)
        _detect_download_behavior(hits, stripped, line_lower, line_number)
        _detect_pipe_to_interpreter(hits, stripped, line_number)
        _detect_interpreter_one_liners(hits, stripped, line_lower, line_number)
        _detect_reverse_shells(hits, stripped, line_number)
        _detect_encoded_execution(hits, stripped, line_number)
        _detect_temp_or_user_exec(hits, stripped, line_lower, line_number)
        _detect_ld_hijack(hits, stripped, line_number)
        _detect_path_hijack(hits, stripped, line_number)
        _detect_stealth_or_privilege_changes(hits, stripped, line_lower, line_number)
        _detect_suspicious_direct_exec(hits, stripped, line_lower, line_number)

    _apply_compound_behavior_bonuses(hits)

    return _finalize_finding(path, hits)

def _detect_exec_hooks(hits, line, line_lower, line_number):
    match = EXEC_HOOK_KEYS.match(line)
    if not match:
        return

    value = match.group(2).strip()
    value_lower = value.lower()

    if any(x in value_lower for x in [
        "/tmp/", "/dev/shm/", "/var/tmp/",
        "curl", "wget", "nc"
    ]):
        _record_hit(
            hits,
            reason="Network hook executes suspicious payload",
            score=90,
            preview=_with_line_number(line_number, line),
            category="exec-risk",
        )


def _detect_dns_abuse(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    match = DNS_KEY_REGEX.match(line)
    if not match:
        return

    value = match.group(2).strip()

    if URL_REGEX.search(value):
        _record_hit(
            hits,
            reason="Network configuration uses a URL-based DNS resolver",
            score=70,
            preview=_with_line_number(line_number, line),
            category="dns-abuse",
        )

    if _path_startswith_any(value.lower(), TEMP_PATH_PATTERNS):
        _record_hit(
            hits,
            reason="DNS configuration references a temporary path",
            score=90,
            preview=_with_line_number(line_number, line),
            category="dns-temp",
        )


def _detect_route_or_policy_hooks(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    match = ROUTE_HOOK_REGEX.match(line)
    if not match:
        return

    value = match.group(2).strip()

    if _contains_high_risk_path(value.lower()):
        _record_hit(
            hits,
            reason="Network route or policy executes from a high-risk path",
            score=85,
            preview=_with_line_number(line_number, line),
            category="route-exec",
        )


def _detect_proxy_abuse(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    if not PROXY_REGEX.search(line):
        return

    if URL_REGEX.search(line):
        _record_hit(
            hits,
            reason="Network configuration sets a proxy to an external endpoint",
            score=60,
            preview=_with_line_number(line_number, line),
            category="proxy",
        )


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
            reason="Network hook downloads content from a remote URL",
            score=60,
            preview=_with_line_number(line_number, line),
            category="download",
        )


def _detect_pipe_to_interpreter(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    if PIPE_TO_INTERPRETER_REGEX.search(line):
        _record_hit(
            hits,
            reason="Network hook downloads and executes payload inline",
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
        if any(k in line_lower for k in ("socket", "exec", "eval", "connect")):
            _record_hit(
                hits,
                reason="Network hook contains a high-risk interpreter one-liner",
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
                reason="Network hook contains reverse-shell behavior",
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
            reason="Network hook decodes and executes payload",
            score=95,
            preview=_with_line_number(line_number, line),
            category="decode-exec",
        )


def _detect_temp_or_user_exec(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    if _contains_high_risk_path(line_lower):
        if DIRECT_EXEC_REGEX.search(line):
            _record_hit(
                hits,
                reason="Network hook executes from a high-risk path",
                score=90,
                preview=_with_line_number(line_number, line),
                category="exec-risk",
            )


def _detect_ld_hijack(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    match = LD_HIJACK_REGEX.search(line)
    if match:
        _record_hit(
            hits,
            reason="Network hook sets LD preload or library path",
            score=90,
            preview=_with_line_number(line_number, line),
            category="ld-hijack",
        )


DEFAULT_PATH = "/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin"

def _detect_path_hijack(hits, line, line_number):
    match = PATH_HIJACK_REGEX.search(line)
    if not match:
        return

    path_value = match.group(1).strip()

    # 🔥 Ignore default Ubuntu PATH
    if path_value == DEFAULT_PATH:
        return

    if any(x in path_value for x in ["/tmp", "/dev/shm", "/var/tmp", "/home"]):
        _record_hit(
            hits,
            reason="Network hook modifies PATH to include high-risk location",
            score=85,
            preview=_with_line_number(line_number, line),
            category="path-hijack",
        )


def _detect_stealth_or_privilege_changes(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    for regex in STEALTH_PERSISTENCE_REGEXES:
        if regex.search(line):
            _record_hit(
                hits,
                reason="Network hook modifies privileges or stealth flags",
                score=85,
                preview=_with_line_number(line_number, line),
                category="stealth",
            )


def _detect_suspicious_direct_exec(hits, line, line_lower, line_number):
    if not DIRECT_EXEC_REGEX.search(line):
        return

    if any(x in line_lower for x in [
        "/tmp/", "/dev/shm/", "/var/tmp/",
        "curl", "wget", "nc", "bash -c"
    ]):
        _record_hit(
            hits,
            reason="Network hook executes suspicious command",
            score=70,
            preview=_with_line_number(line_number, line),
            category="direct-exec",
        )


def _apply_compound_behavior_bonuses(hits: dict[str, dict[str, Any]]) -> None:
    categories = {entry["category"] for entry in hits.values()}

    if "download" in categories and "download-exec" in categories:
        _record_hit(
            hits,
            reason="Network hook combines download and execution",
            score=30,
            preview=None,
            category="compound",
        )


def _detect_core_network_file_risk(
    hits: dict[str, dict[str, Any]],
    path: Path,
    content: str,
) -> None:
    if path.name == "hosts":
        if "127.0.0.1" not in content:
            _record_hit(
                hits,
                reason="Hosts file missing localhost entry",
                score=30,
                preview="hosts anomaly",
                category="hosts",
            )


def _finalize_finding(path: Path, hits: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    if "_ownership_flag" in hits and len(hits) == 1:
        return None

    if "_ownership_flag" in hits:
        _record_hit(
            hits,
            reason="Network hook owned by non-root AND contains suspicious behavior",
            score=40,
            preview=f"owner={_owner_from_uid(hits['_ownership_flag']['uid'])}",
            category="ownership",
        )
        del hits["_ownership_flag"]

    if not hits:
        return None

    score = sum(entry["score"] for entry in hits.values())
    reasons = [entry["reason"] for entry in hits.values()]
    preview = next((entry["preview"] for entry in hits.values() if entry.get("preview")), None)

    return {
        "path": str(path),
        "score": score,
        "severity": _severity(score),
        "reason": max(hits.values(), key=lambda x: x["score"])["reason"],
        "reasons": reasons,
        "preview": preview,
    }


def _record_hit(hits, reason, score, preview, category):
    if category not in hits or score > hits[category]["score"]:
        hits[category] = {
            "reason": reason,
            "score": score,
            "preview": preview,
            "category": category,
        }


def _safe_walk(base: Path):
    try:
        return list(base.rglob("*"))
    except Exception:
        return []


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


def _owner_from_uid(uid: int):
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def _path_startswith_any(path_value: str, prefixes: tuple[str, ...]) -> bool:
    return any(path_value.startswith(p) for p in prefixes)


def _contains_high_risk_path(line_lower: str) -> bool:
    return any(p in line_lower for p in TEMP_PATH_PATTERNS) or bool(USER_PATH_REGEX.search(line_lower))


def _with_line_number(n: int, line: str) -> str:
    return f"line {n}: {line.strip()}"


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