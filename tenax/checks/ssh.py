from __future__ import annotations

import hashlib
import pwd
import re
from pathlib import Path
from typing import Any

from tenax.utils import is_file_safe, path_exists

SSH_PATHS = [
    Path("/etc/ssh"),
    Path("/root/.ssh"),
    Path.home() / ".ssh",
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

AUTHORIZED_KEYS_COMMAND_REGEX = re.compile(
    r"""
    ^
    \s*
    command=
    (?P<quote>["'])?
    (?P<value>.*?)
    (?P=quote)?
    (?P<rest>,|ssh-|$)
    """,
    re.IGNORECASE | re.VERBOSE,
)

AUTHORIZED_KEYS_ENV_REGEX = re.compile(
    r'\benvironment="[^"]+"',
    re.IGNORECASE,
)

AUTHORIZED_KEYS_FROM_REGEX = re.compile(
    r'\bfrom="[^"]+"',
    re.IGNORECASE,
)

SSH_CONFIG_EXEC_REGEX = re.compile(
    r"""
    ^
    \s*
    (
        ProxyCommand|
        LocalCommand|
        Match|
        PermitOpen|
        AuthorizedKeysCommand|
        ForceCommand
    )
    \s+(.+)
    $
    """,
    re.IGNORECASE | re.VERBOSE,
)

AUTHORIZED_KEYS_KEYTYPE_REGEX = re.compile(
    r"^(ssh-(rsa|ed25519|dss)|ecdsa-sha2-[^\s]+|sk-ssh-[^\s]+)",
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

SSH_METADATA_PREFIXES = (
    "host ",
    "match ",
    "include ",
    "user ",
    "hostname ",
    "port ",
    "identityfile ",
    "pubkeyauthentication ",
    "passwordauthentication ",
)


def analyze_ssh_locations() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in SSH_PATHS:
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


def collect_ssh_locations(hash_files: bool = False) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for base in SSH_PATHS:
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
            reason="SSH artifact symlink points to a temporary path",
            score=95,
            preview=f"symlink -> {target_str}",
            category="temp-target",
        )

    if USER_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="SSH artifact symlink points to a user-controlled path",
            score=90,
            preview=f"symlink -> {target_str}",
            category="user-target",
        )

    if HIDDEN_PATH_REGEX.search(target_str):
        _record_hit(
            hits,
            reason="SSH artifact symlink points to a hidden path",
            score=80,
            preview=f"symlink -> {target_str}",
            category="hidden-target",
        )

    stat_info = _safe_lstat(path)
    if stat_info and stat_info.st_uid != 0:
        _record_hit(
            hits,
            reason="SSH artifact symlink is owned by a non-root account",
            score=75,
            preview=f"owner={_owner_from_uid(stat_info.st_uid)}",
            category="ownership",
        )

    return _finalize_finding(path, hits)


def _analyze_file(path: Path) -> dict[str, Any] | None:
    hits: dict[str, dict[str, Any]] = {}
    path_name = path.name.lower()
    path_str = str(path)

    stat_info = _safe_stat(path)
    if stat_info:
        mode = stat_info.st_mode & 0o777

        if stat_info.st_uid != 0:
            _record_hit(
                hits,
                reason="SSH artifact is owned by a non-root account",
                score=80,
                preview=f"owner={_owner_from_uid(stat_info.st_uid)}",
                category="ownership",
            )

        if mode & 0o002:
            _record_hit(
                hits,
                reason="SSH artifact is world-writable",
                score=100,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )
        elif mode & 0o020:
            _record_hit(
                hits,
                reason="SSH artifact is group-writable",
                score=60,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )

        if path_name == "authorized_keys" and (mode & 0o022):
            _record_hit(
                hits,
                reason="authorized_keys permissions are broader than typical secure defaults",
                score=40,
                preview=f"mode={oct(mode)}",
                category="authorized-keys-perms",
            )

    try:
        raw = path.read_bytes()
    except Exception:
        return _finalize_finding(path, hits)

    if b"\x00" in raw[:4096]:
        _record_hit(
            hits,
            reason="SSH artifact contains binary content instead of expected text configuration",
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

        if stripped.startswith("#"):
            continue

        if _is_metadata_line(stripped, path_name):
            continue

        if path_name == "authorized_keys":
            _detect_authorized_keys_abuse(hits, stripped, line_lower, line_number)

        _detect_ssh_config_exec_abuse(hits, stripped, line_lower, line_number)
        _detect_download_behavior(hits, stripped, line_lower, line_number)
        _detect_pipe_to_interpreter(hits, stripped, line_number)
        _detect_interpreter_one_liners(hits, stripped, line_lower, line_number)
        _detect_reverse_shells(hits, stripped, line_number)
        _detect_encoded_execution(hits, stripped, line_number)
        _detect_temp_or_user_exec(hits, stripped, line_lower, line_number)
        _detect_ld_hijack(hits, stripped, line_number)
        _detect_path_hijack(hits, stripped, line_number)
        _detect_stealth_or_privilege_changes(hits, stripped, line_lower, line_number)

    _detect_sensitive_ssh_path_risk(hits, path_str, path_name)
    _apply_compound_behavior_bonuses(hits)

    return _finalize_finding(path, hits)

def _detect_authorized_keys_abuse(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    stripped = line.strip()

    if not stripped or stripped.startswith("#"):
        return

    is_key_line = AUTHORIZED_KEYS_KEYTYPE_REGEX.match(stripped)

    if not is_key_line and not any(x in stripped for x in ["command=", "environment="]):
        return


    if AUTHORIZED_KEYS_COMMAND_REGEX.search(line):
        _record_hit(
            hits,
            reason="authorized_keys entry uses command= restriction/execution",
            score=55,
            preview=_with_line_number(line_number, line),
            category="authorized-keys-command",
        )

        if _contains_high_risk_path(line_lower):
            _record_hit(
                hits,
                reason="authorized_keys command= references a high-risk path",
                score=95,
                preview=_with_line_number(line_number, line),
                category="authorized-keys-command-risk-path",
            )

        if HIDDEN_PATH_REGEX.search(line):
            _record_hit(
                hits,
                reason="authorized_keys command= references a hidden path",
                score=85,
                preview=_with_line_number(line_number, line),
                category="authorized-keys-command-hidden",
            )


    if AUTHORIZED_KEYS_ENV_REGEX.search(line):
        _record_hit(
            hits,
            reason="authorized_keys entry sets environment= options",
            score=25,  # 🔻 reduced noise
            preview=_with_line_number(line_number, line),
            category="authorized-keys-environment",
        )

        if "ld_preload=" in line_lower or "ld_library_path=" in line_lower:
            _record_hit(
                hits,
                reason="authorized_keys environment= sets LD preload behavior",
                score=95,
                preview=_with_line_number(line_number, line),
                category="authorized-keys-ld-hijack",
            )

        if "path=" in line_lower and _contains_high_risk_path(line_lower):
            _record_hit(
                hits,
                reason="authorized_keys environment= modifies PATH to include a high-risk path",
                score=85,
                preview=_with_line_number(line_number, line),
                category="authorized-keys-path-hijack",
            )


    if AUTHORIZED_KEYS_FROM_REGEX.search(line):
        _record_hit(
            hits,
            reason="authorized_keys entry uses from= restriction (normal hardening)",
            score=2,
            preview=_with_line_number(line_number, line),
            category="authorized-keys-from",
        )


    if not is_key_line:
        if _contains_high_risk_path(line_lower):
            _record_hit(
                hits,
                reason="authorized_keys contains non-key line referencing high-risk path",
                score=90,
                preview=_with_line_number(line_number, line),
                category="authorized-keys-nonstandard",
            )

        elif HIDDEN_PATH_REGEX.search(line):
            _record_hit(
                hits,
                reason="authorized_keys contains non-key line referencing hidden path",
                score=80,
                preview=_with_line_number(line_number, line),
                category="authorized-keys-nonstandard",
            )


def _detect_ssh_config_exec_abuse(
    hits: dict[str, dict[str, Any]],
    line: str,
    line_lower: str,
    line_number: int,
) -> None:
    match = SSH_CONFIG_EXEC_REGEX.match(line)
    if not match:
        return

    key = match.group(1)
    value = match.group(2).strip()
    value_lower = value.lower()

    _record_hit(
        hits,
        reason=f"SSH configuration uses {key}",
        score=25,
        preview=_with_line_number(line_number, line),
        category=f"ssh-config-{key.lower()}",
    )

    if _contains_high_risk_path(value_lower):
        if _path_startswith_any(value_lower, TEMP_PATH_PATTERNS):
            _record_hit(
                hits,
                reason=f"SSH {key} references a temporary path",
                score=95,
                preview=_with_line_number(line_number, line),
                category=f"ssh-config-{key.lower()}-temp",
            )
        elif USER_PATH_REGEX.search(value):
            _record_hit(
                hits,
                reason=f"SSH {key} references a user-controlled path",
                score=90,
                preview=_with_line_number(line_number, line),
                category=f"ssh-config-{key.lower()}-user",
            )

    if HIDDEN_PATH_REGEX.search(value):
        _record_hit(
            hits,
            reason=f"SSH {key} references a hidden path",
            score=80,
            preview=_with_line_number(line_number, line),
            category=f"ssh-config-{key.lower()}-hidden",
        )

    if key.lower() == "authorizedkeyscommand":
        _record_hit(
            hits,
            reason="SSH configuration delegates key lookup to AuthorizedKeysCommand",
            score=45,
            preview=_with_line_number(line_number, line),
            category="ssh-config-authorizedkeyscommand",
        )

    if key.lower() == "forcecommand":
        _record_hit(
            hits,
            reason="SSH configuration forces command execution via ForceCommand",
            score=50,
            preview=_with_line_number(line_number, line),
            category="ssh-config-forcecommand",
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
            reason="SSH artifact downloads content from a remote URL",
            score=60,
            preview=_with_line_number(line_number, line),
            category="download",
        )

    if has_download_tool and any(token in line_lower for token in ("-o ", "--output", "> /", ">> /")):
        if _contains_high_risk_path(line_lower):
            _record_hit(
                hits,
                reason="SSH artifact downloads remote content into a high-risk local path",
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
            reason="SSH artifact pipes downloader output directly into an interpreter",
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
                reason="SSH artifact contains a high-risk interpreter one-liner",
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
                reason="SSH artifact contains reverse-shell or socket-based execution behavior",
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
            reason="SSH artifact decodes content and immediately executes it",
            score=95,
            preview=_with_line_number(line_number, line),
            category="decode-exec",
        )
        return

    for regex in ENCODED_EXEC_REGEXES:
        if regex.search(line):
            _record_hit(
                hits,
                reason="SSH artifact contains encoded payload handling logic",
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
    if not DIRECT_EXEC_REGEX.search(line):
        return

    if _contains_high_risk_path(line_lower):
        if _path_startswith_any(line_lower, TEMP_PATH_PATTERNS):
            _record_hit(
                hits,
                reason="SSH artifact executes content from a temporary path",
                score=90,
                preview=_with_line_number(line_number, line),
                category="temp-exec",
            )
            return

        if USER_PATH_REGEX.search(line):
            _record_hit(
                hits,
                reason="SSH artifact executes content from a user-controlled path",
                score=85,
                preview=_with_line_number(line_number, line),
                category="user-exec",
            )
            return

    if HIDDEN_PATH_REGEX.search(line):
        _record_hit(
            hits,
            reason="SSH artifact references a hidden executable or payload path",
            score=80,
            preview=_with_line_number(line_number, line),
            category="hidden-exec",
        )
        return

    path_matches = re.findall(r"(/[^\s'\";|,]+)", line)
    for matched_path in path_matches:
        matched_lower = matched_path.lower()

        if SUSPICIOUS_FILE_EXT_REGEX.search(matched_path):
            if _path_startswith_any(matched_lower, TEMP_PATH_PATTERNS):
                _record_hit(
                    hits,
                    reason="SSH artifact executes a script or binary from a temporary path",
                    score=90,
                    preview=_with_line_number(line_number, line),
                    category="temp-exec",
                )
                return

            if USER_PATH_REGEX.search(matched_path):
                _record_hit(
                    hits,
                    reason="SSH artifact executes a script or binary from a user-controlled path",
                    score=85,
                    preview=_with_line_number(line_number, line),
                    category="user-exec",
                )
                return

            if HIDDEN_PATH_REGEX.search(matched_path):
                _record_hit(
                    hits,
                    reason="SSH artifact executes a script or binary from a hidden path",
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
            reason=f"SSH artifact sets {variable_name} to a temporary path",
            score=95,
            preview=_with_line_number(line_number, line),
            category="ld-hijack",
        )
        return

    if USER_PATH_REGEX.search(variable_value):
        _record_hit(
            hits,
            reason=f"SSH artifact sets {variable_name} to a user-controlled path",
            score=90,
            preview=_with_line_number(line_number, line),
            category="ld-hijack",
        )
        return

    if HIDDEN_PATH_REGEX.search(variable_value):
        _record_hit(
            hits,
            reason=f"SSH artifact sets {variable_name} to a hidden path",
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
                reason="SSH artifact modifies PATH to include a temporary directory",
                score=85,
                preview=_with_line_number(line_number, line),
                category="path-hijack",
            )
            return

        if USER_PATH_REGEX.search(part):
            _record_hit(
                hits,
                reason="SSH artifact modifies PATH to include a user-controlled directory",
                score=80,
                preview=_with_line_number(line_number, line),
                category="path-hijack",
            )
            return

        if HIDDEN_PATH_REGEX.search(part):
            _record_hit(
                hits,
                reason="SSH artifact modifies PATH to include a hidden directory",
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
                reason="SSH artifact contains stealth or privilege-manipulation logic",
                score=85,
                preview=_with_line_number(line_number, line),
                category="stealth-privilege",
            )
            return


def _detect_sensitive_ssh_path_risk(
    hits: dict[str, dict[str, Any]],
    path_str: str,
    path_name: str,
) -> None:
    path_lower = path_str.lower()

    if path_name in {"authorized_keys", "sshd_config", "config", "rc"}:
        _record_hit(
            hits,
            reason=f"Sensitive SSH persistence surface identified: {path_name}",
            score=10,
            preview=path_str,
            category=f"sensitive-path-{path_name}",
        )

    if _path_startswith_any(path_lower, TEMP_PATH_PATTERNS):
        _record_hit(
            hits,
            reason="SSH artifact resides in a temporary path",
            score=95,
            preview=path_str,
            category="temp-target",
        )
        return

    if USER_PATH_REGEX.search(path_str):
        _record_hit(
            hits,
            reason="SSH artifact resides in a user-controlled path",
            score=70,
            preview=path_str,
            category="user-target",
        )
        return

    if HIDDEN_PATH_REGEX.search(path_str):
        _record_hit(
            hits,
            reason="SSH artifact resides at a hidden path",
            score=80,
            preview=path_str,
            category="hidden-target",
        )

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
            "hidden-exec",
        }
        for category in categories
    ):
        _record_hit(
            hits,
            reason="SSH artifact combines download behavior with active execution logic",
            score=35,
            preview=None,
            category="compound-download-exec",
        )

    if any(
        category.startswith("ssh-config-") or category.startswith("authorized-keys-")
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
            reason="SSH persistence configuration is combined with suspicious execution behavior",
            score=30,
            preview=None,
            category="compound-ssh-config-exec",
        )

    if "path-hijack" in categories and any(
        category in {
            "temp-exec",
            "user-exec",
            "hidden-exec",
            "ld-hijack",
            "authorized-keys-command-risk-path",
            "authorized-keys-path-hijack",
        }
        for category in categories
    ):
        _record_hit(
            hits,
            reason="SSH artifact combines PATH hijacking with suspicious execution behavior",
            score=25,
            preview=None,
            category="compound-path-hijack",
        )

    if "authorized-keys-command" in categories and any(
        category in {
            "authorized-keys-command-risk-path",
            "authorized-keys-command-hidden",
            "authorized-keys-ld-hijack",
            "authorized-keys-path-hijack",
        }
        for category in categories
    ):
        _record_hit(
            hits,
            reason="authorized_keys command= is paired with additional high-risk execution indicators",
            score=30,
            preview=None,
            category="compound-authorized-keys-command",
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
        "authorized-keys-command-risk-path",
        "authorized-keys-command-hidden",
        "authorized-keys-ld-hijack",
        "authorized-keys-path-hijack",
        "ssh-config-authorizedkeyscommand",
        "ssh-config-forcecommand",
        "ssh-config-proxycommand-temp",
        "ssh-config-proxycommand-user",
        "ssh-config-proxycommand-hidden",
        "ssh-config-localcommand-temp",
        "ssh-config-localcommand-user",
        "ssh-config-localcommand-hidden",
        "temp-exec",
        "user-exec",
        "hidden-exec",
        "ld-hijack",
        "path-hijack",
        "download-exec",
        "reverse-shell",
        "decode-exec",
        "stealth-privilege",
        "compound-download-exec",
        "compound-ssh-config-exec",
        "compound-path-hijack",
        "compound-authorized-keys-command",
    }

    low_signal_only_categories = {
        "download",
        "download-to-risk-path",
        "encoded",
        "one-liner",
        "authorized-keys-from",
        "authorized-keys-environment",
        "authorized-keys-command",
        "authorized-keys-perms",
        "sensitive-path-authorized_keys",
        "sensitive-path-sshd_config",
        "sensitive-path-config",
        "sensitive-path-rc",
        "ssh-config-proxycommand",
        "ssh-config-localcommand",
        "ssh-config-match",
        "ssh-config-permitopen",
        "ssh-config-forcecommand",
        "ssh-config-authorizedkeyscommand",
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
        "severity": _severity(score),
        "reason": primary_reason,
        "reasons": reasons,
        "preview": preview,
    }


def _record_hit(
    hits: dict[str, dict[str, Any]],
    reason: str,
    score: int,
    preview: str | None,
    category: str,
) -> None:
    existing = hits.get(category)
    if existing is None or score > int(existing["score"]):
        hits[category] = {
            "reason": reason,
            "score": int(score),
            "preview": preview,
            "category": category,
        }


def _build_collect_record(path: Path, hash_files: bool = False) -> dict[str, Any]:
    record = {
        "path": str(path),
        "type": "artifact",
        "exists": path.exists(),
        "owner": "unknown",
        "permissions": "unknown",
    }

    try:
        stat_info = path.lstat() if path.is_symlink() else path.stat()
        record["permissions"] = oct(stat_info.st_mode & 0o777)
    except Exception:
        pass

    try:
        stat_info = path.lstat() if path.is_symlink() else path.stat()
        record["owner"] = pwd.getpwuid(stat_info.st_uid).pw_name
    except Exception:
        pass

    if hash_files and path.exists() and path.is_file() and not path.is_symlink():
        try:
            record["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        except Exception:
            pass

    return record


def _safe_walk(base: Path) -> list[Path]:
    output: list[Path] = []
    try:
        for child in base.rglob("*"):
            if child.is_file() or child.is_symlink():
                output.append(child)
    except Exception:
        return output
    return output


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


def _owner_from_uid(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def _path_startswith_any(path_value: str, prefixes: tuple[str, ...]) -> bool:
    path_lower = path_value.lower()
    return any(path_lower.startswith(prefix.lower()) for prefix in prefixes)


def _contains_high_risk_path(line_lower: str) -> bool:
    if any(token in line_lower for token in TEMP_PATH_PATTERNS):
        return True
    return bool(USER_PATH_REGEX.search(line_lower))


def _with_line_number(line_number: int, line: str) -> str:
    return f"line {line_number}: {line.strip()}"


def _is_metadata_line(line: str, path_name: str) -> bool:
    line_lower = line.strip().lower()

    if path_name == "authorized_keys":
        # authorized_keys is content-heavy and should not use the generic skip list
        return False

    return any(line_lower.startswith(prefix) for prefix in SSH_METADATA_PREFIXES)


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