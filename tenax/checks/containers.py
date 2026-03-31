from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from tenax.checks.common import (
    build_collect_record,
    owner_from_uid,
    path_startswith_any,
    record_hit,
    safe_lstat,
    safe_stat,
    safe_walk,
    severity_from_score,
    with_line_number,
)
from tenax.utils import is_file_safe, path_exists

CONTAINER_PATHS = [
    Path("/etc/docker"),
    Path("/etc/containers"),
    Path("/var/lib/docker/containers"),
    Path("/var/lib/containers"),
    Path("/usr/share/containers"),
    Path.home() / ".config/containers",
    Path.home() / ".docker",
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

PRIVILEGED_REGEX = re.compile(r"(--privileged\b|privileged\s*:\s*true)", re.IGNORECASE)
HOST_NETWORK_REGEX = re.compile(r"(--network[=\s]+host\b|network_mode\s*:\s*host)", re.IGNORECASE)
HOST_PID_REGEX = re.compile(r"(--pid[=\s]+host\b|pid\s*:\s*host)", re.IGNORECASE)
HOST_IPC_REGEX = re.compile(r"(--ipc[=\s]+host\b|ipc\s*:\s*host)", re.IGNORECASE)
DOCKER_SOCK_REGEX = re.compile(r"/var/run/docker\.sock|/run/docker\.sock", re.IGNORECASE)
PODMAN_SOCK_REGEX = re.compile(r"/run/podman/podman\.sock", re.IGNORECASE)
BIND_MOUNT_REGEX = re.compile(
    r"""
    (
        -v\s+[^:\s]+:[^:\s]+ |
        --volume[=\s]+[^:\s]+:[^:\s]+ |
        source\s*:\s*[^:\s]+.*target\s*:\s*[^:\s]+
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

ENTRYPOINT_CMD_REGEX = re.compile(
    r"""
    \b(entrypoint|command|ExecStart|CMD|ENTRYPOINT)\b
    \s*[:=]?\s*
    (.+)
    """,
    re.IGNORECASE | re.VERBOSE,
)

CONTAINER_RUNTIME_REGEX = re.compile(r"\b(docker|podman|containerd|nerdctl)\b", re.IGNORECASE)
CONTAINER_CONFIG_HINT_REGEX = re.compile(
    r"\b(image|entrypoint|command|volumes?|network_mode|pid|ipc|privileged|docker|podman|containerd|nerdctl)\b",
    re.IGNORECASE,
)

_record_hit = record_hit
_safe_walk = safe_walk
_safe_stat = safe_stat
_safe_lstat = safe_lstat
_owner_from_uid = owner_from_uid
_path_startswith_any = path_startswith_any
_with_line_number = with_line_number


def analyze_container_locations() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in CONTAINER_PATHS:
        if not path_exists(base):
            continue

        if base.is_dir():
            for child in safe_walk(base):
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


def collect_container_locations(hash_files: bool = False) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in CONTAINER_PATHS:
        if not path_exists(base):
            continue

        if base.is_dir():
            for child in safe_walk(base):
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
            reason="Container-related symlink target points into a temporary execution path",
            score=95,
            preview=f"symlink -> {target_str}",
            category="temp-target",
        )

    if USER_PATH_REGEX.search(target_str):
        record_hit(
            hits,
            reason="Container-related symlink target points into a user-controlled path",
            score=90,
            preview=f"symlink -> {target_str}",
            category="user-target",
        )

    if HIDDEN_PATH_REGEX.search(target_str):
        record_hit(
            hits,
            reason="Container-related symlink target references a hidden path",
            score=80,
            preview=f"symlink -> {target_str}",
            category="hidden-target",
        )

    stat_info = safe_lstat(path)
    if stat_info and stat_info.st_uid != 0:
        owner_name = owner_from_uid(stat_info.st_uid)
        record_hit(
            hits,
            reason="Container-related symlink is owned by a non-root account",
            score=75,
            preview=f"owner={owner_name}",
            category="ownership",
        )

    return _finalize_finding(path, hits)


def _analyze_file(path: Path) -> dict[str, Any] | None:
    hits: dict[str, dict[str, Any]] = {}

    stat_info = safe_stat(path)
    if stat_info:
        mode = stat_info.st_mode & 0o777
        owner_name = owner_from_uid(stat_info.st_uid)

        if stat_info.st_uid != 0:
            record_hit(
                hits,
                reason="Container-related file is owned by a non-root account",
                score=75,
                preview=f"owner={owner_name}",
                category="ownership",
            )

        if mode & 0o002:
            record_hit(
                hits,
                reason="Container-related file is world-writable",
                score=100,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )
        elif mode & 0o020:
            record_hit(
                hits,
                reason="Container-related file is group-writable",
                score=60,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )

    try:
        raw = path.read_bytes()
    except Exception:
        return _finalize_finding(path, hits)

    if b"\x00" in raw[:4096]:
        record_hit(
            hits,
            reason="Container-related artifact contains binary content",
            score=70,
            preview="[binary content omitted]",
            category="binary",
        )
        return _finalize_finding(path, hits)

    try:
        content = raw.decode("utf-8", errors="ignore")
    except Exception:
        return _finalize_finding(path, hits)

    if not _looks_like_container_artifact(path, content):
        return None

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue

        line_lower = stripped.lower()

        _detect_privileged_or_host_namespace(hits, stripped, line_number)
        _detect_socket_exposure(hits, stripped, line_number)
        _detect_bind_mount_risk(hits, stripped, line_lower, line_number)
        _detect_exec_or_entrypoint(hits, stripped, line_number)
        _detect_inline_payload_behaviors(hits, stripped, line_lower, line_number)
        _detect_runtime_context(hits, stripped, line_number)

    _apply_compound_behavior_bonuses(hits)

    return _finalize_finding(path, hits)


def _looks_like_container_artifact(path: Path, content: str) -> bool:
    path_lower = str(path).lower()
    if any(token in path_lower for token in ("/docker", "/containers", "container", ".docker")):
        return True

    # Avoid double-reporting plain systemd services through the container module
    # unless the unit actually contains container runtime semantics.
    if path.suffix in {".service", ".timer", ".socket", ".path"} and "/systemd/" in path_lower:
        return bool(CONTAINER_CONFIG_HINT_REGEX.search(content))

    return bool(CONTAINER_CONFIG_HINT_REGEX.search(content))

def _detect_privileged_or_host_namespace(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    if PRIVILEGED_REGEX.search(line):
        _record_hit(
            hits,
            reason="Container configuration enables privileged mode",
            score=100,
            preview=_with_line_number(line_number, line),
            category="privileged",
        )

    if HOST_NETWORK_REGEX.search(line):
        _record_hit(
            hits,
            reason="Container configuration uses host network namespace",
            score=70,
            preview=_with_line_number(line_number, line),
            category="host-network",
        )

    if HOST_PID_REGEX.search(line):
        _record_hit(
            hits,
            reason="Container configuration uses host PID namespace",
            score=85,
            preview=_with_line_number(line_number, line),
            category="host-pid",
        )

    if HOST_IPC_REGEX.search(line):
        _record_hit(
            hits,
            reason="Container configuration uses host IPC namespace",
            score=75,
            preview=_with_line_number(line_number, line),
            category="host-ipc",
        )


def _detect_socket_exposure(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    if DOCKER_SOCK_REGEX.search(line):
        _record_hit(
            hits,
            reason="Container configuration exposes the Docker socket",
            score=100,
            preview=_with_line_number(line_number, line),
            category="docker-sock",
        )

    if PODMAN_SOCK_REGEX.search(line):
        _record_hit(
            hits,
            reason="Container configuration exposes the Podman socket",
            score=90,
            preview=_with_line_number(line_number, line),
            category="podman-sock",
        )


def _detect_bind_mount_risk(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    if not BIND_MOUNT_REGEX.search(line):
        return

    path_matches = re.findall(r"(/[^\s:'\",]+)", line)
    for matched_path in path_matches:
        matched_lower = matched_path.lower()

        if _path_startswith_any(matched_lower, TEMP_PATH_PATTERNS):
            _record_hit(
                hits,
                reason="Container bind mount references a temporary host path",
                score=95,
                preview=_with_line_number(line_number, line),
                category="temp-mount",
            )
            return

        if USER_PATH_REGEX.search(matched_path):
            _record_hit(
                hits,
                reason="Container bind mount references a user-controlled host path",
                score=90,
                preview=_with_line_number(line_number, line),
                category="user-mount",
            )
            return

        if HIDDEN_PATH_REGEX.search(matched_path):
            _record_hit(
                hits,
                reason="Container bind mount references a hidden host path",
                score=80,
                preview=_with_line_number(line_number, line),
                category="hidden-mount",
            )
            return

        if matched_lower in {"/", "/etc", "/root", "/var/run/docker.sock", "/run/docker.sock"}:
            _record_hit(
                hits,
                reason="Container bind mount exposes a highly sensitive host path",
                score=95,
                preview=_with_line_number(line_number, line),
                category="sensitive-mount",
            )
            return


def _detect_exec_or_entrypoint(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    match = ENTRYPOINT_CMD_REGEX.search(line)
    if not match:
        return

    value = match.group(2).strip()
    value_lower = value.lower()

    if _path_startswith_any(value_lower, TEMP_PATH_PATTERNS):
        _record_hit(
            hits,
            reason="Container entrypoint or command executes from a temporary path",
            score=95,
            preview=_with_line_number(line_number, line),
            category="temp-exec",
        )
    elif USER_PATH_REGEX.search(value):
        _record_hit(
            hits,
            reason="Container entrypoint or command executes from a user-controlled path",
            score=90,
            preview=_with_line_number(line_number, line),
            category="user-exec",
        )

    if HIDDEN_PATH_REGEX.search(value):
        _record_hit(
            hits,
            reason="Container entrypoint or command references a hidden payload path",
            score=80,
            preview=_with_line_number(line_number, line),
            category="hidden-path",
        )

    executable_paths = re.findall(r"(/[^\s'\";|]+)", value)
    for executable_path in executable_paths:
        lowered = executable_path.lower()

        if _path_startswith_any(lowered, TEMP_PATH_PATTERNS):
            continue
        if USER_PATH_REGEX.search(executable_path):
            continue
        if executable_path.startswith(("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/")):
            continue

        _record_hit(
            hits,
            reason="Container entrypoint or command references a non-standard executable path",
            score=55,
            preview=_with_line_number(line_number, line),
            category="nonstandard-exec",
        )
        break


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
            reason="Container configuration contains network download behavior",
            score=60,
            preview=_with_line_number(line_number, line),
            category="download",
        )

    if PIPE_TO_INTERPRETER_REGEX.search(line):
        _record_hit(
            hits,
            reason="Container configuration downloads and executes payload inline",
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
                reason="Container configuration contains a high-risk interpreter one-liner",
                score=70,
                preview=_with_line_number(line_number, line),
                category="one-liner",
            )

    for regex in SOCKET_IMPLANT_REGEXES:
        if regex.search(line):
            _record_hit(
                hits,
                reason="Container configuration contains reverse-shell or socket-based execution behavior",
                score=100,
                preview=_with_line_number(line_number, line),
                category="reverse-shell",
            )
            break

    if ENCODED_TO_EXEC_REGEX.search(line):
        _record_hit(
            hits,
            reason="Container configuration decodes content and immediately executes it",
            score=95,
            preview=_with_line_number(line_number, line),
            category="decode-exec",
        )
        return

    for regex in ENCODED_EXEC_REGEXES:
        if regex.search(line):
            _record_hit(
                hits,
                reason="Container configuration contains encoded payload handling logic",
                score=45,
                preview=_with_line_number(line_number, line),
                category="encoded",
            )
            break


def _detect_runtime_context(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_number: int,
) -> None:
    if CONTAINER_RUNTIME_REGEX.search(line):
        _record_hit(
            hits,
            reason="Container-related artifact contains runtime execution context",
            score=10,
            preview=_with_line_number(line_number, line),
            category="runtime-context",
        )


def _apply_compound_behavior_bonuses(hits: dict[str, dict[str, Any]]) -> None:
    categories = {entry["category"] for entry in hits.values()}

    if "privileged" in categories and any(
        category in {"docker-sock", "podman-sock", "host-network", "host-pid", "host-ipc"}
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Privileged container configuration is combined with host-level access mechanisms",
            score=35,
            preview=None,
            category="compound-host-access",
        )

    if any("download" in category for category in categories) and any(
        category in {"download-exec", "reverse-shell", "one-liner", "decode-exec"}
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Container configuration combines download behavior with active execution logic",
            score=35,
            preview=None,
            category="compound-download-exec",
        )

    if "temp-mount" in categories and any(
        category in {"temp-exec", "download-exec", "reverse-shell"}
        for category in categories
    ):
        _record_hit(
            hits,
            reason="Container configuration combines temporary-path mounts with suspicious execution",
            score=35,
            preview=None,
            category="compound-temp-exec",
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
        "ownership",
        "permissions",
        "binary",
        "privileged",
        "docker-sock",
        "podman-sock",
        "host-pid",
        "temp-mount",
        "user-mount",
        "hidden-mount",
        "sensitive-mount",
        "temp-exec",
        "user-exec",
        "hidden-path",
        "download-exec",
        "reverse-shell",
        "decode-exec",
        "compound-host-access",
        "compound-download-exec",
        "compound-temp-exec",
    }

    low_signal_only_categories = {
        "download",
        "encoded",
        "runtime-context",
        "host-network",
        "host-ipc",
        "nonstandard-exec",
        "one-liner",
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
        "severity": severity_from_score(score),
        "reason": primary_reason,
        "reasons": reasons,
        "preview": preview,
    }
