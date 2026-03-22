from __future__ import annotations

import hashlib
import pwd
import re
from pathlib import Path
from typing import Any

from tenax.utils import is_file_safe, path_exists

AUTOSTART_PATHS = [
    Path("/etc/xdg/autostart"),
    Path("/usr/share/autostart"),
    Path.home() / ".config/autostart",
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

EXEC_LINE_REGEX = re.compile(r"^Exec=(.+)", re.IGNORECASE)
HIDDEN_FLAG_REGEX = re.compile(r"^Hidden\s*=\s*true", re.IGNORECASE)
AUTOSTART_ENABLED_REGEX = re.compile(r"^X-GNOME-Autostart-enabled\s*=\s*true", re.IGNORECASE)

DOWNLOAD_TOOL_REGEX = re.compile(
    r"\b(curl|wget|fetch|ftpget|tftp|lwp-download|busybox\s+wget)\b",
    re.IGNORECASE,
)

PIPE_TO_INTERPRETER_REGEX = re.compile(
    r"""
    \b(curl|wget)\b.*?(\||;\s*).*?\b(sh|bash|python|perl|php)\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

ENCODED_REGEX = re.compile(r"\bbase64\b.*(-d|--decode)", re.IGNORECASE)

REVERSE_SHELL_REGEX = re.compile(
    r"""
    /dev/tcp/|
    \bnc(?:at)?\b.*\s-e\s|
    \bsocat\b.*exec:
    """,
    re.IGNORECASE | re.VERBOSE,
)


def analyze_autostart_hook_locations() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in AUTOSTART_PATHS:
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

                finding = _analyze_file(child)
                if finding:
                    findings.append(finding)

    return findings


def _analyze_file(path: Path) -> dict[str, Any] | None:
    hits: dict[str, dict[str, Any]] = {}

    stat_info = _safe_stat(path)
    if stat_info:
        if stat_info.st_uid != 0:
            _record_hit(
                hits,
                reason="Autostart entry owned by non-root account",
                score=60,
                preview=f"owner={_owner_from_uid(stat_info.st_uid)}",
                category="ownership",
            )

    try:
        content = path.read_text(errors="ignore")
    except Exception:
        return None

    exec_line = None
    hidden_flag = False

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue

        if EXEC_LINE_REGEX.match(stripped):
            exec_line = EXEC_LINE_REGEX.match(stripped).group(1)
            _analyze_exec_line(hits, exec_line, line_number)

        if HIDDEN_FLAG_REGEX.match(stripped):
            hidden_flag = True

        if AUTOSTART_ENABLED_REGEX.match(stripped):
            _record_hit(
                hits,
                reason="Autostart entry explicitly enabled",
                score=10,
                preview=_with_line_number(line_number, stripped),
                category="enabled",
            )

    if hidden_flag and exec_line:
        _record_hit(
            hits,
            reason="Autostart entry is hidden but still defines execution",
            score=70,
            preview=f"Exec={exec_line}",
            category="hidden-exec",
        )

    return _finalize_finding(path, hits)

def _analyze_exec_line(
    hits: dict[str, dict[str, Any]],
    exec_line: str,
    line_number: int,
) -> None:
    lower = exec_line.lower()

    if any(p in lower for p in TEMP_PATH_PATTERNS):
        _record_hit(
            hits,
            reason="Autostart executes from a temporary path",
            score=90,
            preview=_with_line_number(line_number, exec_line),
            category="temp-exec",
        )

    if USER_PATH_REGEX.search(exec_line):
        _record_hit(
            hits,
            reason="Autostart executes from user-controlled path",
            score=85,
            preview=_with_line_number(line_number, exec_line),
            category="user-exec",
        )

    if HIDDEN_PATH_REGEX.search(exec_line):
        _record_hit(
            hits,
            reason="Autostart references hidden payload path",
            score=80,
            preview=_with_line_number(line_number, exec_line),
            category="hidden-path",
        )

    if DOWNLOAD_TOOL_REGEX.search(exec_line):
        _record_hit(
            hits,
            reason="Autostart contains network download behavior",
            score=60,
            preview=_with_line_number(line_number, exec_line),
            category="download",
        )

    if PIPE_TO_INTERPRETER_REGEX.search(exec_line):
        _record_hit(
            hits,
            reason="Autostart downloads and executes payload inline",
            score=100,
            preview=_with_line_number(line_number, exec_line),
            category="download-exec",
        )

    if ENCODED_REGEX.search(exec_line):
        _record_hit(
            hits,
            reason="Autostart decodes base64 payload",
            score=70,
            preview=_with_line_number(line_number, exec_line),
            category="encoded",
        )

    if REVERSE_SHELL_REGEX.search(exec_line):
        _record_hit(
            hits,
            reason="Autostart contains reverse shell behavior",
            score=100,
            preview=_with_line_number(line_number, exec_line),
            category="reverse-shell",
        )


def _finalize_finding(path: Path, hits: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    if not hits:
        return None

    reasons = [v["reason"] for v in hits.values()]
    previews = [v["preview"] for v in hits.values() if v.get("preview")]
    categories = {v["category"] for v in hits.values()}
    score = sum(v["score"] for v in hits.values())

    high_conf = {
        "temp-exec",
        "user-exec",
        "hidden-path",
        "download-exec",
        "reverse-shell",
    }

    if not (categories & high_conf) and score < 90:
        return None

    primary_reason = max(hits.values(), key=lambda x: x["score"])["reason"]

    return {
        "path": str(path),
        "score": score,
        "severity": _severity(score),
        "reason": primary_reason,
        "reasons": reasons,
        "preview": previews[0] if previews else None,
    }


def _record_hit(hits, reason, score, preview, category):
    if category not in hits or score > hits[category]["score"]:
        hits[category] = {
            "reason": reason,
            "score": score,
            "preview": preview,
            "category": category,
        }


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