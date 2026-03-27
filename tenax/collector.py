from __future__ import annotations

import getpass
import grp
import hashlib
import os
import pwd
import posixpath
import re
import shutil
import socket
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from tenax.checks import BUILTIN_MODULES, COLLECT_SOURCES
from tenax.collector_errors import build_error, categorize_exception
from tenax.collector_output import write_collection_outputs
from tenax.output_paths import resolve_collection_root, resolve_runtime_output_dir
from tenax.scope import (
    apply_module_scope,
    build_scan_scope,
    build_watched_location_paths,
    normalize_path_string,
)


TEXT_PREVIEW_CHARS = 400
COLLECTION_SCHEMA_VERSION = "2.0"
DEFAULT_HASH_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_TEXT_CAPTURE_MAX_BYTES = 2 * 1024 * 1024
DEFAULT_REFERENCE_DEPTH = 2
DEFAULT_LOCATION_TREE_DEPTH = 4
DEFAULT_EXCLUDE_PATTERNS = (
    "/proc/",
    "/sys/",
    "/dev/pts/",
    "/run/user/",
    "/usr/share/doc/",
    "/usr/share/man/",
    "/usr/share/help/",
    "/usr/share/info/",
)
COLLECTION_MODE_PROFILES: dict[str, dict[str, Any]] = {
    "minimal": {
        "description": "Minimal preservation-oriented collection.",
        "copies_direct_artifacts": True,
        "copies_references": True,
        "persist_text_capture": False,
        "parsed_detail_level": "minimal",
    },
    "structured": {
        "description": "Structured investigator-grade collection.",
        "copies_direct_artifacts": False,
        "copies_references": False,
        "persist_text_capture": True,
        "parsed_detail_level": "structured",
    },
    "evidence": {
        "description": "Full evidence bundle with parsed investigator context and preserved artifacts.",
        "copies_direct_artifacts": True,
        "copies_references": True,
        "persist_text_capture": True,
        "parsed_detail_level": "structured",
    },
}

CHECK_REGISTRY: dict[str, Callable[..., list[dict[str, Any]]]] = dict(COLLECT_SOURCES)

# Compatibility shim for older tests and callers that expect this name.
WATCHED_LOCATION_PATHS: dict[str, list[str]] = {}

REFERENCE_PATTERNS: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "ssh": [
        ("path", re.compile(r'(?:(?:command|AuthorizedKeysCommand|ForceCommand)\s*=?\s*|^)\s*["\']?(/[^"\';|,\s]+)', re.IGNORECASE)),
        ("path", re.compile(r'\b(?:IdentityFile|UserKnownHostsFile|GlobalKnownHostsFile)\s+(/[^"\';|,\s]+)', re.IGNORECASE)),
        ("path", re.compile(r'\bLD_PRELOAD\s*=\s*["\']?([^"\';\s]+)', re.IGNORECASE)),
    ],
    "pam": [
        ("path", re.compile(r'\b(?:envfile|conffile|user_envfile)\s*=\s*([^\s]+)', re.IGNORECASE)),
        ("path", re.compile(r'(?:(?:pam_exec\.so).*)(/[^\s"\';|,]+)', re.IGNORECASE)),
        ("path", re.compile(r'^\s*(?:include|substack)\s+(/[^"\';|,\s]+)', re.IGNORECASE)),
        ("path", re.compile(r'^\s*(?:auth|account|password|session)\s+\S+\s+(/[^\s"\';|,]+)', re.IGNORECASE)),
    ],
    "shell_profiles": [
        ("path", re.compile(r'\b(?:source|\.)\s+(/[^"\';|,\s]+)', re.IGNORECASE)),
        ("path", re.compile(r'\b(?:BASH_ENV|ENV|PYTHONSTARTUP|LD_PRELOAD|LD_LIBRARY_PATH)\s*=\s*["\']?([^"\';\s]+)', re.IGNORECASE)),
        ("path", re.compile(r'(/[^\s"\';|,]+(?:\.sh|\.py|\.pl|\.rb|\.php|\.so|\.bin|\.out)?)', re.IGNORECASE)),
        ("url", re.compile(r'\b(https?|ftp|tftp)://[^\s\'"<>]+', re.IGNORECASE)),
    ],
    "environment_hooks": [
        ("path", re.compile(r'\b(?:BASH_ENV|ENV|PYTHONSTARTUP|LD_PRELOAD|LD_LIBRARY_PATH)\s*=\s*["\']?([^"\';\s]+)', re.IGNORECASE)),
        ("path", re.compile(r'\b(?:source|\.)\s+(/[^"\';|,\s]+)', re.IGNORECASE)),
        ("path", re.compile(r'(/[^\s"\';|,]+(?:\.sh|\.py|\.pl|\.rb|\.php|\.so|\.bin|\.out)?)', re.IGNORECASE)),
        ("url", re.compile(r'\b(https?|ftp|tftp)://[^\s\'"<>]+', re.IGNORECASE)),
    ],
    "ld_preload": [
        ("path", re.compile(r'\bLD_PRELOAD\s*=\s*["\']?([^"\';\s]+)', re.IGNORECASE)),
        ("path", re.compile(r'\bLD_LIBRARY_PATH\s*=\s*["\']?([^"\';\n]+)', re.IGNORECASE)),
        ("path", re.compile(r'(/[^\s"\';|,]+\.so(?:\.\d+)*)', re.IGNORECASE)),
    ],
    "network_hooks": [
        ("path", re.compile(r'^\s*(?:ExecStart|ExecStartPre|ExecStartPost|ExecStop|ExecStopPost|pre-up|up|post-up|down|post-down|script|command|run)\s*[:=]?\s*(/[^\s"\';|,]+)', re.IGNORECASE)),
        ("path", re.compile(r'(/[^\s"\';|,]+(?:\.sh|\.py|\.pl|\.rb|\.php|\.so|\.bin|\.out)?)', re.IGNORECASE)),
        ("url", re.compile(r'\b(https?|ftp|tftp)://[^\s\'"<>]+', re.IGNORECASE)),
    ],
    "tmp_paths": [
        ("path", re.compile(r'(/[^\s"\';|,]+(?:\.sh|\.py|\.pl|\.rb|\.php|\.so|\.bin|\.out)?)', re.IGNORECASE)),
        ("url", re.compile(r'\b(https?|ftp|tftp)://[^\s\'"<>]+', re.IGNORECASE)),
    ],
    "systemd": [
        ("path", re.compile(r'^\s*(?:ExecStart|ExecStartPre|ExecStartPost|ExecStop|ExecReload)\s*=\s*([^\s"\';|,]+)', re.IGNORECASE)),
        ("path", re.compile(r'^\s*Environment\s*=\s*["\']?([^"\']+)', re.IGNORECASE)),
    ],
    "cron": [
        ("path", re.compile(r'(/[^\s"\';|,]+(?:\.sh|\.py|\.pl|\.rb|\.php|\.so|\.bin|\.out)?)', re.IGNORECASE)),
        ("url", re.compile(r'\b(https?|ftp|tftp)://[^\s\'"<>]+', re.IGNORECASE)),
    ],
    "rc_init": [
        ("path", re.compile(r'(/[^\s"\';|,]+(?:\.sh|\.py|\.pl|\.rb|\.php|\.so|\.bin|\.out)?)', re.IGNORECASE)),
    ],
    "autostart_hooks": [
        ("path", re.compile(r'^\s*Exec\s*=\s*([^\s"\';|,]+)', re.IGNORECASE)),
        ("path", re.compile(r'(/[^\s"\';|,]+(?:\.sh|\.py|\.pl|\.rb|\.php|\.so|\.bin|\.out)?)', re.IGNORECASE)),
    ],
}


@dataclass
class CollectionOptions:
    mode: str = "structured"
    modules: list[str] = field(default_factory=lambda: list(CHECK_REGISTRY.keys()))
    output_dir: Path = Path("tenax/output")
    hash_files: bool = True
    content: bool = True
    copy_files: bool = False
    archive: bool = False
    follow_references: bool = True
    parse_references: bool = True
    copy_references: bool = False
    include_missing: bool = True
    include_binaries: bool = False
    max_file_size: int = DEFAULT_TEXT_CAPTURE_MAX_BYTES
    max_hash_size: int = DEFAULT_HASH_MAX_BYTES
    max_reference_depth: int = DEFAULT_REFERENCE_DEPTH
    baseline_name: str | None = None
    exclude_patterns: tuple[str, ...] = DEFAULT_EXCLUDE_PATTERNS
    root_prefix: Path | None = None
    persist_text_capture: bool = True
    parsed_detail_level: str = "structured"
    mode_description: str = ""


@dataclass
class ContentCapture:
    mode: str | None = None
    encoding: str | None = None
    line_count: int | None = None
    full_text: str | None = None
    truncated_text: str | None = None
    preview: str | None = None
    truncated: bool = False


@dataclass
class CopyStatus:
    copied: bool = False
    copied_to: str | None = None
    archive_member_path: str | None = None


@dataclass
class ReferenceRecord:
    id: str
    ref_type: str
    value: str
    reason: str
    parent_path: str
    parent_module: str
    depth: int
    discovery_method: str = "module_reference"
    classification: str = "generic"
    collection_required: bool = False
    parent_artifact_id: str | None = None
    resolved_artifact_id: str | None = None
    resolved: str | None = None
    host_resolved: str | None = None
    exists: bool | None = None
    followed: bool = False
    copied: bool = False
    copy_path: str | None = None
    parse_attempted: bool = False
    errors: list[str] = field(default_factory=list)


@dataclass
class ArtifactRecord:
    id: str
    collection_mode: str
    module: str
    artifact_type: str
    path: str
    normalized_path: str
    host_path: str | None
    discovery_mode: str
    discovered_from: str | None
    reference_reason: str | None
    exists: bool
    is_file: bool
    is_dir: bool
    is_symlink: bool
    symlink_target: str | None
    owner: str | None
    group: str | None
    mode: str | None
    size: int | None
    inode: int | None
    mtime: str | None
    ctime: str | None
    sha256: str | None
    preview: str | None
    content_capture: ContentCapture
    parsed: dict[str, Any]
    evidence: dict[str, Any]
    rationale: dict[str, Any]
    lineage: dict[str, Any]
    limitations: list[str]
    references: list[ReferenceRecord]
    copy_status: CopyStatus
    module_metadata: dict[str, Any]
    errors: list[str] = field(default_factory=list)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_owner(uid: int | None) -> str | None:
    if uid is None:
        return None
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def _safe_group(gid: int | None) -> str | None:
    if gid is None:
        return None
    try:
        return grp.getgrgid(gid).gr_name
    except Exception:
        return str(gid)


def _safe_stat(path: Path, follow_symlinks: bool = True):
    try:
        return path.stat() if follow_symlinks else path.lstat()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def _compute_sha256(path: Path, max_bytes: int) -> str | None:
    try:
        stat_info = _safe_stat(path, follow_symlinks=True)
        if stat_info is None:
            return None
        if not path.is_file():
            return None
        if stat_info.st_size > max_bytes:
            return None
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _looks_binary(raw: bytes) -> bool:
    if not raw:
        return False
    return b"\x00" in raw[:4096]


def _read_text_capture(path: Path, max_bytes: int) -> ContentCapture:
    capture = ContentCapture()
    try:
        raw = path.read_bytes()
    except Exception:
        return capture

    if _looks_binary(raw):
        capture.mode = "binary"
        capture.preview = "[binary content omitted]"
        return capture

    try:
        text = raw.decode("utf-8", errors="ignore")
    except Exception:
        capture.mode = "unreadable"
        return capture

    lines = text.splitlines()
    capture.encoding = "utf-8"
    capture.line_count = len(lines)
    capture.preview = text[:TEXT_PREVIEW_CHARS]

    if len(raw) <= max_bytes:
        capture.mode = "full_text"
        capture.full_text = text
        return capture

    capture.mode = "truncated_text"
    capture.truncated = True
    capture.truncated_text = text[:max_bytes]
    return capture


def _normalize_path(path_value: str) -> str:
    return normalize_path_string(path_value)


def _should_skip_path(path_value: str, exclude_patterns: tuple[str, ...]) -> bool:
    lowered = path_value.lower()
    return any(token.lower() in lowered for token in exclude_patterns)


def _artifact_kind_from_path(path: Path, module: str) -> str:
    name = path.name.lower()
    if module == "ssh":
        if name == "authorized_keys":
            return "authorized_keys"
        if name == "sshd_config":
            return "sshd_config"
        if name == "config":
            return "ssh_config"
        return "ssh_artifact"
    if module == "pam":
        return "pam_config"
    if module == "shell_profiles":
        return "shell_profile"
    if module == "environment_hooks":
        return "environment_hook"
    if module == "ld_preload":
        return "ld_preload_config"
    if module == "network_hooks":
        return "network_hook"
    if module == "tmp_paths":
        return "tmp_artifact"
    if module == "systemd":
        return "systemd_artifact"
    if module == "cron":
        return "cron_artifact"
    if module == "sudoers":
        return "sudoers_artifact"
    if module == "rc_init":
        return "rc_init_artifact"
    if module == "autostart_hooks":
        return "autostart_artifact"
    if module == "at_jobs":
        return "at_job_artifact"
    if module == "containers":
        return "container_artifact"
    if module == "capabilities":
        return "capability_artifact"
    return "artifact"


def _extract_module_metadata(raw: dict[str, Any]) -> dict[str, Any]:
    ignored = {"path", "type", "exists", "owner", "permissions", "sha256"}
    return {k: v for k, v in raw.items() if k not in ignored}


def _sanitize_path_component(path_str: str) -> str:
    return path_str.strip("/").replace("/", "_").replace(":", "")


def _copy_preserve_path(src: Path, dst_root: Path, module: str, logical_path: str | None = None) -> CopyStatus:
    copy_status = CopyStatus()
    try:
        base_dir = dst_root / "collected" / module
        base_dir.mkdir(parents=True, exist_ok=True)

        path_for_layout = _normalize_path(logical_path or str(src))
        if path_for_layout.startswith("/"):
            parent_path = posixpath.dirname(path_for_layout)
        else:
            parent_path = str(Path(path_for_layout).parent)
        safe_path = _sanitize_path_component(parent_path)
        dst = base_dir / safe_path / src.name

        dst.parent.mkdir(parents=True, exist_ok=True)

        if src.is_symlink():
            target = os.readlink(src)
            if dst.exists() or dst.is_symlink():
                dst.unlink()
            os.symlink(target, dst)
        else:
            shutil.copy2(src, dst)

        copy_status.copied = True
        copy_status.copied_to = str(dst)
        copy_status.archive_member_path = str(dst.relative_to(dst_root))
        return copy_status
    except Exception:
        return copy_status


def _parse_basic(lines: list[str]) -> dict[str, Any]:
    return {"line_count": len(lines)}


def _validate_collection_mode(mode: str | None) -> str:
    if not mode:
        raise ValueError("collection mode is required")
    if mode not in COLLECTION_MODE_PROFILES:
        supported = ", ".join(sorted(COLLECTION_MODE_PROFILES))
        raise ValueError(f"unsupported collection mode '{mode}'; expected one of: {supported}")
    return mode


def _build_reference_id(parent_path: str, value: str, depth: int) -> str:
    basis = f"{parent_path}|{value}|{depth}"
    return f"ref-{hashlib.sha1(basis.encode('utf-8')).hexdigest()[:12]}"


def _classify_reference(module: str, line: str, ref_type: str, value: str) -> tuple[str, bool]:
    if ref_type != "path":
        return "remote", False

    line_lower = line.lower()
    value_lower = value.lower()
    execution_keywords = (
        "execstart",
        "execstop",
        "authorizedkeyscommand",
        "forcecommand",
        "command=",
        "pam_exec.so",
        "source ",
        ". ",
        "bash_env",
        "pythonstartup",
        "ld_preload",
        "ld_library_path",
        "envfile",
        "conffile",
        "user_envfile",
        "cmnd_alias",
        "@reboot",
    )
    supporting_keywords = (
        "include",
        "includedir",
        "substack",
        "identityfile",
        "userknownhostsfile",
        "globalknownhostsfile",
        "environmentfile",
        "workingdirectory",
        "path=",
    )
    execution_modules = {
        "cron",
        "systemd",
        "pam",
        "shell_profiles",
        "environment_hooks",
        "ld_preload",
        "network_hooks",
        "rc_init",
        "autostart_hooks",
        "sudoers",
        "tmp_paths",
    }

    if any(token in line_lower for token in execution_keywords):
        return "execution", True
    if any(token in line_lower for token in supporting_keywords):
        return "supporting", True
    if module in execution_modules and value_lower.endswith((".sh", ".py", ".pl", ".rb", ".php", ".so", ".bin", ".out")):
        return "execution", True
    if module in execution_modules:
        return "supporting", True
    return "generic", False


def _build_reference_record(
    *,
    module: str,
    parent_path: str,
    line: str,
    ref_type: str,
    value: str,
    depth: int,
    discovery_method: str,
) -> ReferenceRecord:
    classification, collection_required = _classify_reference(module, line, ref_type, value)
    reason = f"{module} {classification} reference extraction"
    return ReferenceRecord(
        id=_build_reference_id(parent_path, value, depth),
        ref_type=ref_type,
        value=value,
        reason=reason,
        parent_path=parent_path,
        parent_module=module,
        depth=depth,
        discovery_method=discovery_method,
        classification=classification,
        collection_required=collection_required,
    )


def _trim_capture_for_mode(capture: ContentCapture, options: CollectionOptions) -> ContentCapture:
    if options.persist_text_capture:
        return capture
    return ContentCapture(
        mode=capture.mode,
        encoding=capture.encoding,
        line_count=capture.line_count,
        preview=capture.preview,
        truncated=capture.truncated,
    )


def _extract_paths(value: str) -> list[str]:
    return sorted({match.group(0) for match in re.finditer(r"/[^\s\"';|,]+", value)})


def _extract_urls(value: str) -> list[str]:
    return sorted({match.group(0) for match in re.finditer(r"(?:https?|ftp|tftp)://[^\s'\"<>]+", value)})


def _parse_systemd_content(lines: list[str]) -> dict[str, Any]:
    directives: list[dict[str, Any]] = []
    exec_entries: list[dict[str, Any]] = []
    env_files: list[str] = []
    working_directories: list[str] = []
    run_as: dict[str, str] = {}
    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith(("#", ";")) or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip()
        directives.append({"line": line_number, "key": key, "value": value})
        if key.startswith("Exec"):
            exec_entries.append(
                {
                    "line": line_number,
                    "directive": key,
                    "command": value,
                    "paths": _extract_paths(value),
                    "urls": _extract_urls(value),
                }
            )
        if key == "EnvironmentFile":
            env_files.extend(_extract_paths(value.lstrip("-")))
        if key == "WorkingDirectory":
            working_directories.extend(_extract_paths(value))
        if key in {"User", "Group"}:
            run_as[key.lower()] = value
    return {
        "format": "systemd-unit",
        "line_count": len(lines),
        "exec_entries": exec_entries,
        "environment_files": sorted(set(env_files)),
        "working_directories": sorted(set(working_directories)),
        "run_as": run_as,
        "directives": directives[:25],
    }


def _parse_cron_content(lines: list[str]) -> dict[str, Any]:
    jobs: list[dict[str, Any]] = []
    variables: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" in stripped and not re.match(r"^(@\w+|\S+\s+\S+\s+\S+\s+\S+\s+\S+)", stripped):
            name, value = stripped.split("=", 1)
            variables.append({"line": line_number, "name": name.strip(), "value": value.strip()})
            continue
        match = re.match(r"^(@\w+|\S+\s+\S+\s+\S+\s+\S+\s+\S+(?:\s+\S+)?)\s+(.+)$", stripped)
        if not match:
            continue
        schedule = match.group(1)
        command = match.group(2)
        jobs.append(
            {
                "line": line_number,
                "schedule": schedule,
                "command": command,
                "paths": _extract_paths(command),
                "urls": _extract_urls(command),
            }
        )
    return {"format": "cron", "line_count": len(lines), "jobs": jobs, "variables": variables}


def _parse_pam_content(lines: list[str]) -> dict[str, Any]:
    modules: list[dict[str, Any]] = []
    includes: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        include_match = re.match(r"^(include|substack)\s+(\S+)$", stripped, re.IGNORECASE)
        if include_match:
            includes.append(
                {
                    "line": line_number,
                    "keyword": include_match.group(1),
                    "target": include_match.group(2),
                }
            )
            continue
        module_match = re.match(r"^(auth|account|password|session)\s+(\[[^\]]+\]|\S+)\s+(\S+)(.*)$", stripped, re.IGNORECASE)
        if module_match:
            args = (module_match.group(4) or "").strip()
            modules.append(
                {
                    "line": line_number,
                    "type": module_match.group(1),
                    "control": module_match.group(2),
                    "module": module_match.group(3),
                    "args": args,
                    "paths": _extract_paths(args),
                }
            )
    return {"format": "pam", "line_count": len(lines), "modules": modules, "includes": includes}


def _parse_shell_profile_content(lines: list[str]) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    assignments: list[dict[str, Any]] = []
    hooks: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("source ") or stripped.startswith(". "):
            sources.append({"line": line_number, "statement": stripped, "paths": _extract_paths(stripped)})
        if "=" in stripped and not stripped.startswith("alias "):
            name, value = stripped.split("=", 1)
            assignments.append({"line": line_number, "name": name.strip(), "value": value.strip(), "paths": _extract_paths(value)})
        if any(token in stripped for token in ("PROMPT_COMMAND", "trap ", "alias ")):
            hooks.append({"line": line_number, "statement": stripped, "paths": _extract_paths(stripped)})
    return {
        "format": "shell-profile",
        "line_count": len(lines),
        "sourced_files": sources,
        "assignments": assignments[:25],
        "hooks": hooks,
    }


def _parse_sudoers_content(lines: list[str]) -> dict[str, Any]:
    includes: list[dict[str, Any]] = []
    defaults: list[dict[str, Any]] = []
    aliases: list[dict[str, Any]] = []
    privilege_specs: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        include_match = re.match(r"^#?(include|includedir)\s+(.+)$", stripped, re.IGNORECASE)
        if include_match:
            includes.append({"line": line_number, "directive": include_match.group(1), "value": include_match.group(2).strip()})
            continue
        alias_match = re.match(r"^Cmnd_Alias\s+([A-Za-z0-9_]+)\s*=\s*(.+)$", stripped)
        if alias_match:
            aliases.append({"line": line_number, "name": alias_match.group(1), "value": alias_match.group(2), "paths": _extract_paths(alias_match.group(2))})
            continue
        if stripped.startswith("Defaults"):
            defaults.append({"line": line_number, "value": stripped})
            continue
        if not stripped.startswith("#"):
            privilege_specs.append({"line": line_number, "value": stripped, "paths": _extract_paths(stripped)})
    return {
        "format": "sudoers",
        "line_count": len(lines),
        "includes": includes,
        "defaults": defaults,
        "command_aliases": aliases,
        "privilege_specs": privilege_specs,
    }


def _parse_artifact_content(module: str, lines: list[str], detail_level: str) -> dict[str, Any]:
    basic = _parse_basic(lines)
    if detail_level == "minimal":
        return basic
    if module == "systemd":
        return _parse_systemd_content(lines)
    if module == "cron":
        return _parse_cron_content(lines)
    if module == "pam":
        return _parse_pam_content(lines)
    if module in {"shell_profiles", "environment_hooks"}:
        return _parse_shell_profile_content(lines)
    if module == "sudoers":
        return _parse_sudoers_content(lines)
    return basic


def _build_artifact_rationale(
    *,
    options: CollectionOptions,
    module: str,
    path: str,
    discovery_mode: str,
    discovered_from: str | None,
    reference_reason: str | None,
    references: list[ReferenceRecord],
    content_capture: ContentCapture,
    parsed: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    why_collected = [f"{module} collection enumerated this persistence surface."]
    if discovery_mode == "reference" and discovered_from:
        why_collected.append(f"Collected because {discovered_from} referenced this path.")
    if reference_reason:
        why_collected.append(reference_reason)
    if any(ref.collection_required for ref in references):
        why_collected.append("Execution-linked or support-linked references were identified from this artifact.")

    limitations: list[str] = []
    if content_capture.mode == "binary":
        limitations.append("Binary content was not rendered as text.")
    if content_capture.truncated:
        limitations.append("Text capture was truncated by max-file-size.")
    if not options.persist_text_capture and content_capture.preview:
        limitations.append("Full text content was intentionally omitted by the selected collection mode.")

    return (
        {
            "summary": f"{module} artifact collected in {options.mode} mode.",
            "why_collected": why_collected,
            "how_discovered": {
                "discovery_mode": discovery_mode,
                "discovered_from": discovered_from,
                "reference_reason": reference_reason,
            },
            "investigator_value": {
                "parsed_format": parsed.get("format", "basic"),
                "reference_count": len(references),
                "preview_available": bool(content_capture.preview),
            },
        },
        limitations,
    )


def _build_artifact_lineage(
    *,
    artifact_id: str,
    options: CollectionOptions,
    module: str,
    discovery_mode: str,
    discovered_from: str | None,
    host_path: str | None,
    parent_artifact_id: str | None = None,
) -> dict[str, Any]:
    return {
        "artifact_id": artifact_id,
        "collection_mode": options.mode,
        "module": module,
        "discovery_mode": discovery_mode,
        "discovered_from": discovered_from,
        "parent_artifact_id": parent_artifact_id,
        "host_path": host_path,
    }


def _build_artifact_evidence(content_capture: ContentCapture, parsed: dict[str, Any]) -> dict[str, Any]:
    return {
        "preview": content_capture.preview,
        "content_capture_mode": content_capture.mode,
        "line_count": content_capture.line_count,
        "parsed_format": parsed.get("format", "basic"),
    }


def _extract_references(module: str, parent_path: str, lines: list[str]) -> list[ReferenceRecord]:
    refs: list[ReferenceRecord] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for ref_type, pattern in REFERENCE_PATTERNS.get(module, []):
            for match in pattern.finditer(stripped):
                value = match.group(1).strip()
                if not value:
                    continue
                if ref_type == "path":
                    value = _normalize_path(value)
                refs.append(
                    _build_reference_record(
                        module=module,
                        parent_path=parent_path,
                        line=stripped,
                        ref_type=ref_type,
                        value=value,
                        depth=1,
                        discovery_method="module_reference",
                    )
                )
    deduped: dict[tuple[str, str, str], ReferenceRecord] = {}
    for ref in refs:
        deduped[(ref.ref_type, ref.value, ref.classification)] = ref
    return list(deduped.values())


def _resolve_reference_path(value: str, scope_context) -> str | None:
    normalized = _normalize_path(value)
    if not normalized:
        return None
    return str(scope_context.resolve_host_path(normalized))


def _should_follow_reference(ref: ReferenceRecord, options: CollectionOptions) -> bool:
    if ref.ref_type != "path":
        return False
    if not ref.value.startswith("/"):
        return False
    if _should_skip_path(ref.value, options.exclude_patterns):
        return False
    if ref.collection_required:
        return True
    return options.follow_references

def _format_permissions(path: Path) -> str:
    stat_info = _safe_stat(path, follow_symlinks=False)
    if stat_info is None:
        return "unknown"
    return oct(stat_info.st_mode & 0o777)


def _format_owner(path: Path) -> str:
    stat_info = _safe_stat(path, follow_symlinks=False)
    if stat_info is None:
        return "unknown"
    return _safe_owner(stat_info.st_uid) or "unknown"


def _tree_label(path: Path) -> str:
    try:
        if path.is_dir():
            return f"{path.name}/" if path.name else str(path)
        return path.name or str(path)
    except Exception:
        return path.name or str(path)


def _build_location_tree(
    path: Path,
    display_path: str,
    indent: int = 0,
    max_depth: int = DEFAULT_LOCATION_TREE_DEPTH,
) -> list[str]:
    lines: list[str] = []
    prefix = "    " * indent

    lstat_info = _safe_stat(path, follow_symlinks=False)
    stat_info = _safe_stat(path, follow_symlinks=True)

    exists = bool(lstat_info or stat_info)

    if not exists:
        if indent == 0:
            lines.append(f"{display_path}  (Missing)")
        else:
            lines.append(f"{prefix}----{path.name}  (Missing)")
        return lines

    is_dir = bool(stat_info and path.is_dir())

    name = display_path if indent == 0 else (path.name + "/" if is_dir else path.name)
    perm = oct(((stat_info or lstat_info).st_mode) & 0o777) if (stat_info or lstat_info) else "unknown"
    owner = _safe_owner((stat_info or lstat_info).st_uid if (stat_info or lstat_info) else None)

    if indent == 0:
        lines.append(f"{name}  (Permissions) {perm}  (Creator) {owner}")
    else:
        lines.append(f"{prefix}----{name}  (Permissions) {perm}  (Creator) {owner}")

    if not is_dir:
        return lines

    if indent >= max_depth:
        return lines

    try:
        children = sorted(
            list(path.iterdir()),
            key=lambda p: (not p.is_dir(), p.name.lower()),
        )
    except (PermissionError, OSError):
        lines.append(f"{prefix}    ----[Permission Denied]")
        return lines

    for child in children:
        lines.extend(
            _build_location_tree(
                child,
                display_path=child.name + ("/" if child.is_dir() else ""),
                indent=indent + 1,
                max_depth=max_depth,
            )
        )

    return lines


def _build_watched_locations_inventory(modules: list[str], scope_context) -> dict[str, list[str]]:
    inventory: dict[str, list[str]] = {}
    watched_paths = build_watched_location_paths(modules, scope_context)

    for module in modules:
        module_paths = watched_paths.get(module, [])
        module_lines: list[str] = []

        for raw_path in module_paths:
            path = scope_context.resolve_host_path(raw_path)
            module_lines.extend(_build_location_tree(path, display_path=raw_path))
            module_lines.append("")

        while module_lines and module_lines[-1] == "":
            module_lines.pop()

        inventory[module] = module_lines

    return inventory


def _ingest_direct_artifact(
    module: str,
    raw: dict[str, Any],
    options: CollectionOptions,
    artifact_index: int,
    evidence_root: Path | None,
    scope_context,
) -> tuple[ArtifactRecord | None, list[ReferenceRecord], list[dict[str, Any]]]:
    errors: list[dict[str, Any]] = []
    host_path = _normalize_path(str(raw.get("path", "")).strip())
    if not host_path:
        errors.append(
            build_error(
                error_type="parse_failure",
                module=module,
                message="Collector module returned an artifact without a usable path.",
            )
        )
        return None, [], errors

    normalized_path = scope_context.target_path_from_host(host_path) or host_path
    if _should_skip_path(normalized_path, options.exclude_patterns):
        return None, [], errors

    path = Path(host_path)
    lstat_info = _safe_stat(path, follow_symlinks=False)
    stat_info = _safe_stat(path, follow_symlinks=True)

    exists = bool(lstat_info or stat_info)
    if not exists and not options.include_missing:
        errors.append(
            build_error(
                error_type="missing_path",
                module=module,
                path=normalized_path,
                message="Artifact path was missing and include-missing is disabled.",
            )
        )
        return None, [], errors

    is_symlink = bool(lstat_info and path.is_symlink())
    is_file = bool(stat_info and path.is_file())
    is_dir = bool(stat_info and path.is_dir())

    symlink_target = None
    if is_symlink:
        try:
            resolved_symlink = str(path.resolve(strict=False))
            symlink_target = scope_context.target_path_from_host(resolved_symlink) or resolved_symlink
        except Exception:
            symlink_target = None

    owner = _safe_owner((stat_info or lstat_info).st_uid if (stat_info or lstat_info) else None)
    group = _safe_group((stat_info or lstat_info).st_gid if (stat_info or lstat_info) else None)
    mode = oct(((stat_info or lstat_info).st_mode) & 0o777) if (stat_info or lstat_info) else None
    size = (stat_info or lstat_info).st_size if (stat_info or lstat_info) else None
    inode = (stat_info or lstat_info).st_ino if (stat_info or lstat_info) else None
    mtime = datetime.fromtimestamp((stat_info or lstat_info).st_mtime, tz=timezone.utc).isoformat() if (stat_info or lstat_info) else None
    ctime = datetime.fromtimestamp((stat_info or lstat_info).st_ctime, tz=timezone.utc).isoformat() if (stat_info or lstat_info) else None

    sha256 = raw.get("sha256")
    if sha256 is None and options.hash_files and exists and is_file:
        sha256 = _compute_sha256(path, options.max_hash_size)

    content_capture = ContentCapture()
    parsed: dict[str, Any] = {}
    references: list[ReferenceRecord] = []

    artifact_id = f"artifact-{artifact_index:06d}"

    if exists and is_file and options.content:
        content_capture = _read_text_capture(path, options.max_file_size)
        text = content_capture.full_text if content_capture.full_text is not None else content_capture.truncated_text
        if text:
            lines = text.splitlines()
            parsed = _parse_artifact_content(module, lines, options.parsed_detail_level)
            if options.parse_references:
                references = _extract_references(module, normalized_path, lines)
        content_capture = _trim_capture_for_mode(content_capture, options)

    preview = content_capture.preview or raw.get("preview")
    for ref in references:
        ref.parent_artifact_id = artifact_id

    copy_status = CopyStatus()
    if options.copy_files and evidence_root and exists and (is_file or is_symlink):
        copy_status = _copy_preserve_path(path, evidence_root, module, logical_path=normalized_path)

    rationale, limitations = _build_artifact_rationale(
        options=options,
        module=module,
        path=normalized_path,
        discovery_mode="direct",
        discovered_from=None,
        reference_reason=None,
        references=references,
        content_capture=content_capture,
        parsed=parsed,
    )

    artifact = ArtifactRecord(
        id=artifact_id,
        collection_mode=options.mode,
        module=module,
        artifact_type=_artifact_kind_from_path(path, module),
        path=normalized_path,
        normalized_path=normalized_path,
        host_path=host_path,
        discovery_mode="direct",
        discovered_from=None,
        reference_reason=None,
        exists=exists,
        is_file=is_file,
        is_dir=is_dir,
        is_symlink=is_symlink,
        symlink_target=symlink_target,
        owner=owner or raw.get("owner"),
        group=group,
        mode=mode or raw.get("permissions"),
        size=size,
        inode=inode,
        mtime=mtime,
        ctime=ctime,
        sha256=sha256,
        preview=preview,
        content_capture=content_capture,
        parsed=parsed,
        evidence=_build_artifact_evidence(content_capture, parsed),
        rationale=rationale,
        lineage=_build_artifact_lineage(
            artifact_id=artifact_id,
            options=options,
            module=module,
            discovery_mode="direct",
            discovered_from=None,
            host_path=host_path,
        ),
        limitations=limitations,
        references=references,
        copy_status=copy_status,
        module_metadata={
            **_extract_module_metadata(raw),
            "target_path": normalized_path,
            "host_path": host_path,
        },
        errors=[],
    )
    return artifact, references, errors


def _generic_extract_references(parent_path: str, capture: ContentCapture, depth: int) -> list[ReferenceRecord]:
    text = capture.full_text if capture.full_text is not None else capture.truncated_text
    if not text:
        return []

    refs: list[ReferenceRecord] = []
    path_re = re.compile(r'(/[^\s"\';|,]+(?:\.sh|\.py|\.pl|\.rb|\.php|\.so|\.bin|\.out)?)', re.IGNORECASE)
    url_re = re.compile(r'\b(https?|ftp|tftp)://[^\s\'"<>]+', re.IGNORECASE)

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for m in path_re.finditer(stripped):
            value = _normalize_path(m.group(1))
            refs.append(
                _build_reference_record(
                    module="generic",
                    parent_path=parent_path,
                    line=stripped,
                    ref_type="path",
                    value=value,
                    depth=depth,
                    discovery_method="generic_reference",
                )
            )
        for m in url_re.finditer(stripped):
            refs.append(
                _build_reference_record(
                    module="generic",
                    parent_path=parent_path,
                    line=stripped,
                    ref_type="url",
                    value=m.group(0),
                    depth=depth,
                    discovery_method="generic_reference",
                )
            )
    deduped: dict[tuple[str, str, str], ReferenceRecord] = {}
    for ref in refs:
        deduped[(ref.ref_type, ref.value, ref.classification)] = ref
    return list(deduped.values())


def _ingest_reference_artifact(
    ref: ReferenceRecord,
    options: CollectionOptions,
    artifact_index: int,
    evidence_root: Path | None,
    scope_context,
) -> tuple[ArtifactRecord | None, list[ReferenceRecord], list[dict[str, Any]]]:
    errors: list[dict[str, Any]] = []
    host_resolved = _resolve_reference_path(ref.value, scope_context)
    ref.host_resolved = host_resolved
    ref.resolved = _normalize_path(ref.value)
    if host_resolved is None:
        ref.errors.append("failed to normalize reference path")
        errors.append(
            build_error(
                error_type="parse_failure",
                module=ref.parent_module,
                path=ref.value,
                message="Reference path could not be normalized.",
            )
        )
        return None, [], errors

    if _should_skip_path(ref.resolved or ref.value, options.exclude_patterns):
        ref.errors.append("reference path skipped by exclude patterns")
        return None, [], errors

    path = Path(host_resolved)

    lstat_info = _safe_stat(path, follow_symlinks=False)
    stat_info = _safe_stat(path, follow_symlinks=True)

    exists = bool(lstat_info or stat_info)
    ref.exists = exists
    if not exists:
        errors.append(
            build_error(
                error_type="missing_path",
                module=ref.parent_module,
                path=ref.resolved or ref.value,
                message="Referenced path did not exist at collection time.",
            )
        )
        return None, [], errors

    is_symlink = bool(lstat_info and path.is_symlink())
    is_file = bool(stat_info and path.is_file())
    is_dir = bool(stat_info and path.is_dir())

    if is_dir:
        errors.append(
            build_error(
                error_type="parse_failure",
                module=ref.parent_module,
                path=ref.resolved or ref.value,
                message="Referenced path resolved to a directory and was not ingested as an artifact.",
            )
        )
        return None, [], errors

    symlink_target = None
    if is_symlink:
        try:
            resolved_symlink = str(path.resolve(strict=False))
            symlink_target = scope_context.target_path_from_host(resolved_symlink) or resolved_symlink
        except Exception:
            symlink_target = None

    owner = _safe_owner((stat_info or lstat_info).st_uid if (stat_info or lstat_info) else None)
    group = _safe_group((stat_info or lstat_info).st_gid if (stat_info or lstat_info) else None)
    mode = oct(((stat_info or lstat_info).st_mode) & 0o777) if (stat_info or lstat_info) else None
    size = (stat_info or lstat_info).st_size if (stat_info or lstat_info) else None
    inode = (stat_info or lstat_info).st_ino if (stat_info or lstat_info) else None
    mtime = datetime.fromtimestamp((stat_info or lstat_info).st_mtime, tz=timezone.utc).isoformat() if (stat_info or lstat_info) else None
    ctime = datetime.fromtimestamp((stat_info or lstat_info).st_ctime, tz=timezone.utc).isoformat() if (stat_info or lstat_info) else None

    sha256 = _compute_sha256(path, options.max_hash_size) if options.hash_files and is_file else None
    content_capture = ContentCapture()
    nested_refs: list[ReferenceRecord] = []
    parsed: dict[str, Any] = {}
    artifact_id = f"artifact-{artifact_index:06d}"

    if is_file and options.content and options.parse_references:
        content_capture = _read_text_capture(path, options.max_file_size)
        nested_refs = _generic_extract_references(ref.resolved or ref.value, content_capture, ref.depth + 1)
        ref.parse_attempted = True
        text = content_capture.full_text if content_capture.full_text is not None else content_capture.truncated_text
        if text:
            parsed = _parse_artifact_content(ref.parent_module, text.splitlines(), options.parsed_detail_level)
        content_capture = _trim_capture_for_mode(content_capture, options)
    for nested_ref in nested_refs:
        nested_ref.parent_artifact_id = artifact_id

    copy_status = CopyStatus()
    if options.copy_references and evidence_root and (is_file or is_symlink):
        copy_status = _copy_preserve_path(
            path,
            evidence_root,
            f"{ref.parent_module}_reference",
            logical_path=ref.resolved or ref.value,
        )

    rationale, limitations = _build_artifact_rationale(
        options=options,
        module=f"{ref.parent_module}_reference",
        path=ref.resolved or ref.value,
        discovery_mode="reference",
        discovered_from=ref.parent_path,
        reference_reason=ref.reason,
        references=nested_refs,
        content_capture=content_capture,
        parsed=parsed,
    )

    artifact = ArtifactRecord(
        id=artifact_id,
        collection_mode=options.mode,
        module=f"{ref.parent_module}_reference",
        artifact_type="referenced_artifact",
        path=ref.resolved or ref.value,
        normalized_path=ref.resolved or ref.value,
        host_path=host_resolved,
        discovery_mode="reference",
        discovered_from=ref.parent_path,
        reference_reason=ref.reason,
        exists=True,
        is_file=is_file,
        is_dir=is_dir,
        is_symlink=is_symlink,
        symlink_target=symlink_target,
        owner=owner,
        group=group,
        mode=mode,
        size=size,
        inode=inode,
        mtime=mtime,
        ctime=ctime,
        sha256=sha256,
        preview=content_capture.preview,
        content_capture=content_capture,
        parsed=parsed,
        evidence=_build_artifact_evidence(content_capture, parsed),
        rationale=rationale,
        lineage=_build_artifact_lineage(
            artifact_id=artifact_id,
            options=options,
            module=f"{ref.parent_module}_reference",
            discovery_mode="reference",
            discovered_from=ref.parent_path,
            host_path=host_resolved,
            parent_artifact_id=ref.parent_artifact_id,
        ),
        limitations=limitations,
        references=nested_refs,
        copy_status=copy_status,
        module_metadata={
            "parent_module": ref.parent_module,
            "reference_type": ref.ref_type,
            "target_path": ref.resolved or ref.value,
            "host_path": host_resolved,
            "classification": ref.classification,
        },
        errors=[],
    )
    ref.followed = True
    ref.copied = copy_status.copied
    ref.copy_path = copy_status.copied_to
    ref.resolved_artifact_id = artifact_id
    return artifact, nested_refs, errors

def _summarize(artifacts: list[ArtifactRecord], references: list[ReferenceRecord], errors: list[dict[str, Any]]) -> dict[str, Any]:
    direct_count = sum(1 for a in artifacts if a.discovery_mode == "direct")
    ref_count = sum(1 for a in artifacts if a.discovery_mode == "reference")
    copied_count = sum(1 for a in artifacts if a.copy_status.copied)
    required_reference_count = sum(1 for ref in references if ref.collection_required)
    followed_required_reference_count = sum(1 for ref in references if ref.collection_required and ref.followed)
    module_counts: dict[str, int] = {}
    for artifact in artifacts:
        module_counts[artifact.module] = module_counts.get(artifact.module, 0) + 1
    return {
        "artifact_count": len(artifacts),
        "direct_artifact_count": direct_count,
        "reference_artifact_count": ref_count,
        "reference_count": len(references),
        "required_reference_count": required_reference_count,
        "followed_required_reference_count": followed_required_reference_count,
        "copied_artifact_count": copied_count,
        "module_counts": module_counts,
        "error_count": len(errors),
    }


def _build_limitations(
    options: CollectionOptions,
    errors: list[dict[str, Any]],
    scope_context,
    *,
    module_status: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    limitations: list[dict[str, Any]] = [
        {
            "type": "mode",
            "code": "collection_mode",
            "message": f"Collection ran in {options.mode} mode: {options.mode_description}",
            "mode": options.mode,
        },
        {
            "type": "scope",
            "code": "module_selection",
            "message": "Only the selected collection modules were executed.",
            "modules": options.modules,
        },
        {
            "type": "scope",
            "code": "target_root",
            "message": (
                f"Collection targeted mounted root {scope_context.root_prefix}."
                if scope_context.root_prefix
                else "Collection targeted the live host root."
            ),
            "root_prefix": str(scope_context.root_prefix) if scope_context.root_prefix else None,
            "target_root": scope_context.root_label,
        },
        {
            "type": "scope",
            "code": "user_enumeration",
            "message": f"User-scoped collection paths expanded across {len(scope_context.target_users)} local user home paths.",
            "users": [user.username for user in scope_context.target_users],
            "homes": [user.home for user in scope_context.target_users],
        },
        {
            "type": "references",
            "code": "reference_depth",
            "message": f"Reference following is limited to depth {options.max_reference_depth}.",
            "max_reference_depth": options.max_reference_depth,
            "follow_references": options.follow_references,
        },
    ]

    if options.exclude_patterns:
        limitations.append(
            {
                "type": "paths",
                "code": "excluded_paths",
                "message": "Some paths were excluded from collection and reference following.",
                "exclude_patterns": list(options.exclude_patterns),
            }
        )

    if not options.hash_files:
        limitations.append(
            {
                "type": "hashing",
                "code": "hashing_disabled",
                "message": "SHA256 hashing was disabled for this collection run.",
            }
        )

    if errors:
        limitations.append(
            {
                "type": "partial_coverage",
                "code": "collection_errors",
                "message": "One or more collection modules or artifact ingests reported errors.",
                "error_count": len(errors),
                "error_types": sorted({error.get("type", "module_failure") for error in errors}),
            }
        )

    for status in module_status:
        for limitation in status.get("limitations", []):
            limitations.append({**limitation, "module": status["module"]})

    limitations.append(
        {
            "type": "permissions",
            "code": "access_boundaries",
            "message": "Unreadable target paths, missing mounted content, and excluded paths may reduce collected coverage.",
        }
    )

    return limitations

def run_collection(
    output_path=None,
    hash_files=True,
    mode=None,
    modules: list[str] | None = None,
    follow_references=True,
    archive=False,
    baseline_name: str | None = None,
    max_file_size: int = DEFAULT_TEXT_CAPTURE_MAX_BYTES,
    max_hash_size: int = DEFAULT_HASH_MAX_BYTES,
    max_reference_depth: int = DEFAULT_REFERENCE_DEPTH,
    exclude_patterns: tuple[str, ...] = (),
    root_prefix: Path | None = None,
) -> list[dict[str, Any]]:
    mode = _validate_collection_mode(mode)
    profile = COLLECTION_MODE_PROFILES[mode]
    selected_modules = modules or list(CHECK_REGISTRY.keys())
    effective_exclude_patterns = DEFAULT_EXCLUDE_PATTERNS + tuple(exclude_patterns or ())
    scope_context = build_scan_scope(root_prefix)

    options = CollectionOptions(
        mode=mode,
        modules=selected_modules,
        output_dir=Path(output_path) if output_path else resolve_runtime_output_dir(),
        hash_files=hash_files,
        content=True,
        copy_files=profile["copies_direct_artifacts"],
        archive=archive,
        follow_references=follow_references,
        parse_references=True,
        copy_references=profile["copies_references"],
        include_missing=True,
        include_binaries=False,
        max_file_size=max_file_size,
        max_hash_size=max_hash_size,
        max_reference_depth=max_reference_depth,
        baseline_name=baseline_name,
        exclude_patterns=effective_exclude_patterns,
        root_prefix=scope_context.root_prefix,
        persist_text_capture=profile["persist_text_capture"],
        parsed_detail_level=profile["parsed_detail_level"],
        mode_description=profile["description"],
    )

    collection_id = datetime.now(timezone.utc).strftime("collect_%Y%m%d_%H%M%S")
    host = socket.gethostname()
    user = getpass.getuser()
    root_output_dir = resolve_collection_root(options.output_dir, collection_id)
    (root_output_dir / "collected").mkdir(parents=True, exist_ok=True)

    evidence_root = None
    if options.copy_files or options.copy_references or options.archive:
        evidence_root = root_output_dir

    artifacts: list[ArtifactRecord] = []
    references: list[ReferenceRecord] = []
    errors: list[dict[str, Any]] = []
    module_status: list[dict[str, Any]] = []
    seen_artifact_paths: set[str] = set()
    seen_reference_paths: set[str] = set()
    artifact_index = 1

    with apply_module_scope(options.modules, scope_context):
        for module_name in options.modules:
            collector = CHECK_REGISTRY.get(module_name)
            if collector is None:
                errors.append(
                    build_error(
                        error_type="module_failure",
                        module=module_name,
                        message="Collection module is not registered.",
                    )
                )
                module_status.append({"module": module_name, "ok": False, "limitations": []})
                continue

            try:
                module_artifacts = collector(hash_files=options.hash_files)
            except Exception as exc:
                errors.append(
                    build_error(
                        error_type=categorize_exception(exc),
                        module=module_name,
                        message="Collection module execution failed.",
                        exception=exc,
                    )
                )
                module_status.append({"module": module_name, "ok": False, "limitations": []})
                continue

            module_status.append(
                {
                    "module": module_name,
                    "ok": True,
                    "limitations": getattr(collector, "_tenax_limitations", []),
                }
            )

            for raw in module_artifacts:
                artifact, direct_refs, ingest_errors = _ingest_direct_artifact(
                    module=module_name,
                    raw=raw,
                    options=options,
                    artifact_index=artifact_index,
                    evidence_root=evidence_root,
                    scope_context=scope_context,
                )
                errors.extend(ingest_errors)
                if artifact is None:
                    continue
                if artifact.normalized_path in seen_artifact_paths:
                    continue
                seen_artifact_paths.add(artifact.normalized_path)
                artifacts.append(artifact)
                artifact_index += 1
                references.extend(direct_refs)

    queue: list[ReferenceRecord] = references[:]
    while queue:
        ref = queue.pop(0)
        if ref.ref_type != "path":
            continue
        if ref.depth > options.max_reference_depth:
            ref.errors.append("max reference depth exceeded")
            errors.append(
                build_error(
                    error_type="parse_failure",
                    module=ref.parent_module,
                    path=ref.value,
                    message="Reference was not followed because max-reference-depth was exceeded.",
                    context={"depth": ref.depth, "max_reference_depth": options.max_reference_depth},
                )
            )
            continue
        if not _should_follow_reference(ref, options):
            continue
        resolved = _resolve_reference_path(ref.value, scope_context)
        if not resolved:
            ref.errors.append("failed to resolve reference")
            errors.append(
                build_error(
                    error_type="missing_path",
                    module=ref.parent_module,
                    path=ref.value,
                    message="Reference path could not be resolved.",
                )
            )
            continue
        ref.resolved = _normalize_path(ref.value)
        target_resolved = ref.resolved or ref.value
        if target_resolved in seen_reference_paths or target_resolved in seen_artifact_paths:
            continue
        seen_reference_paths.add(target_resolved)
        artifact, nested_refs, ingest_errors = _ingest_reference_artifact(
            ref=ref,
            options=options,
            artifact_index=artifact_index,
            evidence_root=evidence_root,
            scope_context=scope_context,
        )
        errors.extend(ingest_errors)
        if artifact is None:
            continue
        artifacts.append(artifact)
        artifact_index += 1
        for nested_ref in nested_refs:
            nested_ref.depth = ref.depth + 1
            nested_ref.parent_path = artifact.normalized_path
            nested_ref.parent_module = artifact.module
            references.append(nested_ref)
            queue.append(nested_ref)

    summary = _summarize(artifacts, references, errors)
    location_inventory = _build_watched_locations_inventory(options.modules, scope_context)
    limitations = _build_limitations(options, errors, scope_context, module_status=module_status)

    manifest = {
        "schema_version": COLLECTION_SCHEMA_VERSION,
        "collection_id": collection_id,
        "created_at": _iso_now(),
        "mode": options.mode,
        "mode_description": options.mode_description,
        "host": host,
        "user": user,
        "baseline_name": options.baseline_name,
        "collection_profile": profile,
        "options": {
            "mode": options.mode,
            "modules": options.modules,
            "hash_files": options.hash_files,
            "follow_references": options.follow_references,
            "copy_files": options.copy_files,
            "copy_references": options.copy_references,
            "archive": options.archive,
            "max_file_size": options.max_file_size,
            "max_hash_size": options.max_hash_size,
            "max_reference_depth": options.max_reference_depth,
            "exclude_patterns": list(options.exclude_patterns),
            "root_prefix": str(options.root_prefix) if options.root_prefix else None,
            "persist_text_capture": options.persist_text_capture,
            "parsed_detail_level": options.parsed_detail_level,
        },
        "module_catalog": {
            name: {
                "display_name": module.metadata.display_name,
                "description": module.metadata.description,
                "analyze_contract": module.metadata.analyze_contract,
                "collect_contract": module.metadata.collect_contract,
                "analysis_behavior": module.metadata.analysis_behavior,
                "collection_behavior": module.metadata.collection_behavior,
                "heuristic_profile": {
                    "default_mode": module.metadata.heuristic_profile.default_mode,
                    "supported_modes": list(module.metadata.heuristic_profile.supported_modes),
                },
                "scoring_profile": {
                    "name": module.metadata.scoring_profile.name,
                    "module_score_delta": module.metadata.scoring_profile.module_score_delta,
                    "environment_score_deltas": module.metadata.scoring_profile.environment_score_deltas,
                },
                "scopes": list(module.metadata.scopes),
                "tags": list(module.metadata.tags),
            }
            for name, module in BUILTIN_MODULES.items()
            if name in options.modules
        },
        "summary": summary,
        "scope": {
            "root_prefix": str(scope_context.root_prefix) if scope_context.root_prefix else None,
            "target_root": scope_context.root_label,
            "all_users": [user.username for user in scope_context.target_users],
            "user_homes": [user.home for user in scope_context.target_users],
        },
        "limitations": limitations,
        "module_status": module_status,
        "artifacts": [asdict(a) for a in artifacts],
        "references": [asdict(r) for r in references],
        "errors": errors,
    }

    archive_path = write_collection_outputs(
        root_output_dir=root_output_dir,
        manifest=manifest,
        artifacts=artifacts,
        references=[asdict(r) for r in references],
        errors=errors,
        collection_id=collection_id,
        mode=options.mode,
        host=host,
        user=user,
        baseline_name=options.baseline_name,
        summary=summary,
        location_inventory=location_inventory,
        limitations=limitations,
        archive=options.archive,
    )

    print("=== TENAX COLLECT RESULTS ===")
    print(f"Mode: {options.mode}")
    print(f"Artifacts: {len(artifacts)}")
    print(f"References: {len(references)}")
    print(f"Errors: {len(errors)}")
    print(f"Saved manifest to: {root_output_dir / 'manifest.json'}")
    if archive_path is not None:
        print(f"Saved archive to: {archive_path}")

    return [asdict(a) for a in artifacts]
