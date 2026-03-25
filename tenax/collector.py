from __future__ import annotations

import getpass
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import socket
import tarfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from tenax.checks.at_jobs import collect_at_job_locations
from tenax.checks.autostart_hooks import collect_autostart_hook_locations
from tenax.checks.capabilities import collect_capabilities
from tenax.checks.containers import collect_container_locations
from tenax.checks.cron import collect_cron_locations
from tenax.checks.environment_hooks import collect_environment_hook_locations
from tenax.checks.ld_preload import collect_ld_preload_locations
from tenax.checks.network_hooks import collect_network_hook_locations
from tenax.checks.pam import collect_pam_locations
from tenax.checks.rc_init import collect_rc_init_locations
from tenax.checks.shell_profiles import collect_shell_profile_locations
from tenax.checks.ssh import collect_ssh_locations
from tenax.checks.sudoers import collect_sudoers_locations
from tenax.checks.systemd import collect_systemd_locations
from tenax.checks.tmp_paths import collect_tmp_paths


TEXT_PREVIEW_CHARS = 400
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

CHECK_REGISTRY: dict[str, Callable[..., list[dict[str, Any]]]] = {
    "cron": collect_cron_locations,
    "systemd": collect_systemd_locations,
    "shell_profiles": collect_shell_profile_locations,
    "ssh": collect_ssh_locations,
    "sudoers": collect_sudoers_locations,
    "rc_init": collect_rc_init_locations,
    "tmp_paths": collect_tmp_paths,
    "ld_preload": collect_ld_preload_locations,
    "autostart_hooks": collect_autostart_hook_locations,
    "network_hooks": collect_network_hook_locations,
    "pam": collect_pam_locations,
    "at_jobs": collect_at_job_locations,
    "containers": collect_container_locations,
    "environment_hooks": collect_environment_hook_locations,
    "capabilities": collect_capabilities,
}

WATCHED_LOCATION_PATHS: dict[str, list[str]] = {
    "cron": [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.monthly",
        "/etc/cron.weekly",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
    ],
    "systemd": [
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    ],
    "shell_profiles": [
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/zsh/zshrc",
        "/etc/zshrc",
        "/etc/profile.d",
        "/etc/skel/.bashrc",
        "/etc/skel/.profile",
        "/etc/skel/.zshrc",
        str(Path.home() / ".bashrc"),
        str(Path.home() / ".bash_profile"),
        str(Path.home() / ".profile"),
        str(Path.home() / ".zprofile"),
        str(Path.home() / ".zshrc"),
    ],
    "ssh": [
        "/etc/ssh",
        "/root/.ssh",
        str(Path.home() / ".ssh"),
    ],
    "sudoers": [
        "/etc/sudoers",
        "/etc/sudoers.d",
    ],
    "rc_init": [
        "/etc/init.d",
        "/etc/rc.d",
        "/etc/rc.local",
    ],
    "tmp_paths": [
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/run/shm",
    ],
    "ld_preload": [
        "/etc/ld.so.preload",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        str(Path.home() / ".bashrc"),
        str(Path.home() / ".profile"),
        str(Path.home() / ".zshrc"),
    ],
    "autostart_hooks": [
        "/etc/xdg/autostart",
        str(Path.home() / ".config/autostart"),
    ],
    "network_hooks": [
        "/etc/NetworkManager",
        "/etc/network",
        "/etc/netplan",
        "/etc/systemd/network",
        "/etc/ppp",
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/hostname",
        "/usr/lib/NetworkManager",
        "/usr/lib/systemd/network",
        "/lib/systemd/network",
        str(Path.home() / ".config/NetworkManager"),
    ],
    "pam": [
        "/etc/pam.d",
    ],
    "at_jobs": [
        "/var/spool/cron/atjobs",
        "/var/spool/at",
        "/var/spool/atjobs",
    ],
    "containers": [
        "/etc/docker",
        "/var/lib/docker",
        "/etc/containerd",
        "/var/lib/containerd",
        "/etc/podman",
        "/var/lib/podman",
    ],
    "environment_hooks": [
        "/etc/profile",
        "/etc/environment",
        "/etc/bash.bashrc",
        "/etc/profile.d",
        "/etc/zsh/zshrc",
        "/etc/zshrc",
        str(Path.home() / ".bashrc"),
        str(Path.home() / ".bash_profile"),
        str(Path.home() / ".profile"),
        str(Path.home() / ".zshrc"),
    ],
    "capabilities": [
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
    ],
}

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
    mode: str = "parsed"
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
    ref_type: str
    value: str
    reason: str
    parent_path: str
    parent_module: str
    depth: int
    resolved: str | None = None
    exists: bool | None = None
    followed: bool = False
    copied: bool = False
    copy_path: str | None = None
    parse_attempted: bool = False
    errors: list[str] = field(default_factory=list)


@dataclass
class ArtifactRecord:
    id: str
    module: str
    artifact_type: str
    path: str
    normalized_path: str
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
    try:
        return str(Path(path_value).expanduser())
    except Exception:
        return path_value


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


def _copy_preserve_path(src: Path, dst_root: Path, module: str) -> CopyStatus:
    copy_status = CopyStatus()
    try:
        base_dir = dst_root / "collected" / module
        base_dir.mkdir(parents=True, exist_ok=True)

        safe_path = _sanitize_path_component(str(src.parent))
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
                    ReferenceRecord(
                        ref_type=ref_type,
                        value=value,
                        reason=f"{module} reference extraction",
                        parent_path=parent_path,
                        parent_module=module,
                        depth=1,
                    )
                )
    deduped: dict[tuple[str, str], ReferenceRecord] = {}
    for ref in refs:
        deduped[(ref.ref_type, ref.value)] = ref
    return list(deduped.values())


def _resolve_reference_path(value: str) -> str | None:
    try:
        return str(Path(value).expanduser())
    except Exception:
        return None


def _should_follow_reference(ref: ReferenceRecord, options: CollectionOptions) -> bool:
    if ref.ref_type != "path":
        return False
    if not options.follow_references:
        return False
    if not ref.value.startswith("/"):
        return False
    if _should_skip_path(ref.value, options.exclude_patterns):
        return False
    return True

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
    indent: int = 0,
    max_depth: int = DEFAULT_LOCATION_TREE_DEPTH,
) -> list[str]:
    lines: list[str] = []
    prefix = "    " * indent

    if not path.exists():
        lines.append(f"{prefix}{path}  (Missing)")
        return lines

    name = str(path) if indent == 0 else _tree_label(path)
    perm = _format_permissions(path)
    owner = _format_owner(path)
    kind = "Directory" if path.is_dir() else "File"

    if indent == 0:
        lines.append(f"{name}  (Permissions) {perm}  (Creator) {owner}")
    else:
        lines.append(f"{prefix}----{name}  (Permissions) {perm}  (Creator) {owner}")

    if not path.is_dir():
        return lines

    if indent >= max_depth:
        return lines

    try:
        children = sorted(
            list(path.iterdir()),
            key=lambda p: (not p.is_dir(), p.name.lower()),
        )
    except Exception:
        lines.append(f"{prefix}    ----[Permission Denied]")
        return lines

    for child in children:
        lines.extend(_build_location_tree(child, indent=indent + 1, max_depth=max_depth))

    return lines


def _build_watched_locations_inventory(modules: list[str]) -> dict[str, list[str]]:
    inventory: dict[str, list[str]] = {}

    for module in modules:
        module_paths = WATCHED_LOCATION_PATHS.get(module, [])
        module_lines: list[str] = []

        for raw_path in module_paths:
            path = Path(_normalize_path(raw_path))
            module_lines.extend(_build_location_tree(path))
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
) -> tuple[ArtifactRecord | None, list[ReferenceRecord], list[dict[str, Any]]]:
    errors: list[dict[str, Any]] = []
    raw_path = str(raw.get("path", "")).strip()
    if not raw_path:
        return None, [], errors

    normalized_path = _normalize_path(raw_path)
    if _should_skip_path(normalized_path, options.exclude_patterns):
        return None, [], errors

    path = Path(normalized_path)
    lstat_info = _safe_stat(path, follow_symlinks=False)
    stat_info = _safe_stat(path, follow_symlinks=True)

    exists = bool(lstat_info or stat_info)
    if not exists and not options.include_missing:
        return None, [], errors

    is_symlink = bool(lstat_info and path.is_symlink())
    is_file = bool(stat_info and path.is_file())
    is_dir = bool(stat_info and path.is_dir())

    symlink_target = None
    if is_symlink:
        try:
            symlink_target = str(path.resolve(strict=False))
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

    if exists and is_file and options.content and options.mode in {"parsed", "evidence", "archive"}:
        content_capture = _read_text_capture(path, options.max_file_size)
        text = content_capture.full_text if content_capture.full_text is not None else content_capture.truncated_text
        if text:
            lines = text.splitlines()
            parsed = _parse_basic(lines)
            if options.parse_references:
                references = _extract_references(module, str(path), lines)

    preview = content_capture.preview or raw.get("preview")

    copy_status = CopyStatus()
    if options.copy_files and evidence_root and exists and (is_file or is_symlink):
        copy_status = _copy_preserve_path(path, evidence_root, module)

    artifact = ArtifactRecord(
        id=f"artifact-{artifact_index:06d}",
        module=module,
        artifact_type=_artifact_kind_from_path(path, module),
        path=raw_path,
        normalized_path=normalized_path,
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
        references=references,
        copy_status=copy_status,
        module_metadata=_extract_module_metadata(raw),
        errors=[],
    )
    return artifact, references, errors


def _generic_extract_references(path: Path, capture: ContentCapture, depth: int) -> list[ReferenceRecord]:
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
                ReferenceRecord(
                    ref_type="path",
                    value=value,
                    reason="generic reference extraction",
                    parent_path=str(path),
                    parent_module="generic",
                    depth=depth,
                )
            )
        for m in url_re.finditer(stripped):
            refs.append(
                ReferenceRecord(
                    ref_type="url",
                    value=m.group(0),
                    reason="generic reference extraction",
                    parent_path=str(path),
                    parent_module="generic",
                    depth=depth,
                )
            )
    deduped: dict[tuple[str, str], ReferenceRecord] = {}
    for ref in refs:
        deduped[(ref.ref_type, ref.value)] = ref
    return list(deduped.values())


def _ingest_reference_artifact(
    ref: ReferenceRecord,
    options: CollectionOptions,
    artifact_index: int,
    evidence_root: Path | None,
) -> tuple[ArtifactRecord | None, list[ReferenceRecord], list[dict[str, Any]]]:
    errors: list[dict[str, Any]] = []
    resolved = _resolve_reference_path(ref.value)
    ref.resolved = resolved
    if resolved is None:
        ref.errors.append("failed to normalize reference path")
        return None, [], errors

    if _should_skip_path(resolved, options.exclude_patterns):
        ref.errors.append("reference path skipped by exclude patterns")
        return None, [], errors

    path = Path(resolved)

    lstat_info = _safe_stat(path, follow_symlinks=False)
    stat_info = _safe_stat(path, follow_symlinks=True)

    exists = bool(lstat_info or stat_info)
    ref.exists = exists
    if not exists:
        return None, [], errors

    is_symlink = bool(lstat_info and path.is_symlink())
    is_file = bool(stat_info and path.is_file())
    is_dir = bool(stat_info and path.is_dir())

    if is_dir:
        return None, [], errors

    symlink_target = None
    if is_symlink:
        try:
            symlink_target = str(path.resolve(strict=False))
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

    if is_file and options.content and options.parse_references:
        content_capture = _read_text_capture(path, options.max_file_size)
        nested_refs = _generic_extract_references(path, content_capture, ref.depth + 1)
        ref.parse_attempted = True

    copy_status = CopyStatus()
    if options.copy_references and evidence_root and (is_file or is_symlink):
        copy_status = _copy_preserve_path(path, evidence_root, f"{ref.parent_module}_reference")

    artifact = ArtifactRecord(
        id=f"artifact-{artifact_index:06d}",
        module=f"{ref.parent_module}_reference",
        artifact_type="referenced_artifact",
        path=resolved,
        normalized_path=resolved,
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
        parsed={},
        references=nested_refs,
        copy_status=copy_status,
        module_metadata={"parent_module": ref.parent_module, "reference_type": ref.ref_type},
        errors=[],
    )
    ref.followed = True
    ref.copied = copy_status.copied
    ref.copy_path = copy_status.copied_to
    return artifact, nested_refs, errors

def _summarize(artifacts: list[ArtifactRecord], references: list[ReferenceRecord], errors: list[dict[str, Any]]) -> dict[str, Any]:
    direct_count = sum(1 for a in artifacts if a.discovery_mode == "direct")
    ref_count = sum(1 for a in artifacts if a.discovery_mode == "reference")
    copied_count = sum(1 for a in artifacts if a.copy_status.copied)
    module_counts: dict[str, int] = {}
    for artifact in artifacts:
        module_counts[artifact.module] = module_counts.get(artifact.module, 0) + 1
    return {
        "artifact_count": len(artifacts),
        "direct_artifact_count": direct_count,
        "reference_artifact_count": ref_count,
        "reference_count": len(references),
        "copied_artifact_count": copied_count,
        "module_counts": module_counts,
        "error_count": len(errors),
    }


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def _write_hashes(path: Path, artifacts: list[ArtifactRecord]) -> None:
    lines: list[str] = []
    for artifact in artifacts:
        if artifact.sha256:
            lines.append(f"{artifact.sha256}  {artifact.normalized_path}")
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_summary(
    path: Path,
    collection_id: str,
    mode: str,
    host: str,
    user: str,
    baseline_name: str | None,
    summary: dict[str, Any],
    artifacts: list[ArtifactRecord],
    location_inventory: dict[str, list[str]],
) -> None:
    lines: list[str] = []
    lines.append("=== TENAX COLLECT SUMMARY ===")
    lines.append("")
    lines.append(f"Collection ID: {collection_id}")
    lines.append(f"Mode: {mode}")
    lines.append(f"Host: {host}")
    lines.append(f"User: {user}")
    if baseline_name:
        lines.append(f"Baseline Name: {baseline_name}")
    lines.append("")
    lines.append("--- Totals ---")
    lines.append(f"Artifacts collected: {summary['artifact_count']}")
    lines.append(f"Direct artifacts: {summary['direct_artifact_count']}")
    lines.append(f"Reference artifacts: {summary['reference_artifact_count']}")
    lines.append(f"References found: {summary['reference_count']}")
    lines.append(f"Artifacts copied: {summary['copied_artifact_count']}")
    lines.append(f"Errors: {summary['error_count']}")
    lines.append("")
    lines.append("--- By Module ---")
    for module_name, count in sorted(summary["module_counts"].items()):
        lines.append(f"{module_name}: {count}")
    lines.append("")
    lines.append("--- Watched Locations Inventory ---")
    for module, tree_lines in location_inventory.items():
        lines.append(f"[{module}]")
        for l in tree_lines:
            lines.append(l)
        lines.append("")
    lines.append("--- Collected Artifacts ---")
    for artifact in artifacts:
        lines.append(f"[{artifact.id}] {artifact.module} | {artifact.artifact_type}")
        lines.append(f"Path: {artifact.path}")
        lines.append(f"Discovery: {artifact.discovery_mode}")
        if artifact.discovered_from:
            lines.append(f"Discovered From: {artifact.discovered_from}")
        if artifact.reference_reason:
            lines.append(f"Reference Reason: {artifact.reference_reason}")
        if artifact.sha256:
            lines.append(f"SHA256: {artifact.sha256}")
        if artifact.preview:
            lines.append(f"Preview: {artifact.preview[:TEXT_PREVIEW_CHARS]}")
        if artifact.copy_status.copied and artifact.copy_status.copied_to:
            lines.append(f"Copied To: {artifact.copy_status.copied_to}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")

def _archive_directory(source_dir: Path, archive_path: Path) -> None:
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(source_dir, arcname=source_dir.name)


def run_collection(
    output_path=None,
    output_format="text",
    hash_files=False,
    mode="parsed",
    modules: list[str] | None = None,
    follow_references=True,
    copy_files=False,
    copy_references=False,
    archive=False,
    baseline_name: str | None = None,
    max_file_size: int = DEFAULT_TEXT_CAPTURE_MAX_BYTES,
    max_hash_size: int = DEFAULT_HASH_MAX_BYTES,
    max_reference_depth: int = DEFAULT_REFERENCE_DEPTH,
    exclude_patterns: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    selected_modules = modules or list(CHECK_REGISTRY.keys())
    effective_exclude_patterns = DEFAULT_EXCLUDE_PATTERNS + tuple(exclude_patterns or ())

    options = CollectionOptions(
        mode=mode,
        modules=selected_modules,
        output_dir=Path(output_path) if output_path else Path(__file__).resolve().parent.parent / "output",
        hash_files=hash_files,
        content=mode in {"parsed", "evidence", "archive"},
        copy_files=copy_files or mode in {"evidence", "archive"},
        archive=archive or mode == "archive",
        follow_references=follow_references,
        parse_references=mode in {"parsed", "evidence", "archive"},
        copy_references=copy_references or mode in {"evidence", "archive"},
        include_missing=True,
        include_binaries=False,
        max_file_size=max_file_size,
        max_hash_size=max_hash_size,
        max_reference_depth=max_reference_depth,
        baseline_name=baseline_name,
        exclude_patterns=effective_exclude_patterns,
    )

    collection_id = datetime.now(timezone.utc).strftime("collect_%Y%m%d_%H%M%S")
    host = socket.gethostname()
    user = getpass.getuser()
    root_output_dir = options.output_dir / collection_id
    root_output_dir.mkdir(parents=True, exist_ok=True)
    (root_output_dir / "collected").mkdir(parents=True, exist_ok=True)

    evidence_root = None
    if options.copy_files or options.copy_references or options.archive:
        evidence_root = root_output_dir

    artifacts: list[ArtifactRecord] = []
    references: list[ReferenceRecord] = []
    errors: list[dict[str, Any]] = []
    seen_artifact_paths: set[str] = set()
    seen_reference_paths: set[str] = set()
    artifact_index = 1

    for module_name in options.modules:
        collector = CHECK_REGISTRY.get(module_name)
        if collector is None:
            errors.append({"module": module_name, "error": "module not registered"})
            continue

        try:
            module_artifacts = collector(hash_files=options.hash_files)
        except Exception as e:
            errors.append({"module": module_name, "error": str(e)})
            continue

        for raw in module_artifacts:
            artifact, direct_refs, ingest_errors = _ingest_direct_artifact(
                module=module_name,
                raw=raw,
                options=options,
                artifact_index=artifact_index,
                evidence_root=evidence_root,
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

    if options.follow_references:
        queue: list[ReferenceRecord] = references[:]
        while queue:
            ref = queue.pop(0)
            if ref.ref_type != "path":
                continue
            if ref.depth > options.max_reference_depth:
                ref.errors.append("max reference depth exceeded")
                continue
            if not _should_follow_reference(ref, options):
                continue
            resolved = _resolve_reference_path(ref.value)
            if not resolved:
                ref.errors.append("failed to resolve reference")
                continue
            if resolved in seen_reference_paths or resolved in seen_artifact_paths:
                continue
            seen_reference_paths.add(resolved)
            artifact, nested_refs, ingest_errors = _ingest_reference_artifact(
                ref=ref,
                options=options,
                artifact_index=artifact_index,
                evidence_root=evidence_root,
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
    location_inventory = _build_watched_locations_inventory(options.modules)

    manifest = {
        "collection_id": collection_id,
        "created_at": _iso_now(),
        "mode": options.mode,
        "host": host,
        "user": user,
        "baseline_name": options.baseline_name,
        "summary": summary,
        "artifacts": [asdict(a) for a in artifacts],
        "references": [asdict(r) for r in references],
        "errors": errors,
    }

    _write_json(root_output_dir / "manifest.json", manifest)
    _write_json(root_output_dir / "references.json", [asdict(r) for r in references])
    _write_json(root_output_dir / "errors.json", errors)
    _write_hashes(root_output_dir / "hashes.txt", artifacts)
    _write_summary(
        root_output_dir / "summary.txt",
        collection_id,
        options.mode,
        host,
        user,
        options.baseline_name,
        summary,
        artifacts,
        location_inventory,
    )

    archive_path = None
    if options.archive:
        archive_path = root_output_dir.parent / f"{collection_id}.tgz"
        _archive_directory(root_output_dir, archive_path)

    print("\n" + "=" * 80)
    print("[+] TENAX COLLECTION COMPLETE")
    print("=" * 80)
    print(f"[+] Mode: {options.mode}")
    print(f"[+] Host: {host}")
    print(f"[+] Output Directory: {root_output_dir}")
    print(f"[+] Manifest: {root_output_dir / 'manifest.json'}")
    print(f"[+] Summary: {root_output_dir / 'summary.txt'}")
    print(f"[+] References: {root_output_dir / 'references.json'}")
    print(f"[+] Errors: {root_output_dir / 'errors.json'}")
    print(f"[+] Hashes: {root_output_dir / 'hashes.txt'}")

    if options.copy_files or options.copy_references:
        print("[+] Artifacts copied under:")
        print(f"    - {root_output_dir / 'collected'}")

    if archive_path is not None:
        print(f"[+] Archive: {archive_path}")

    print(f"[+] Artifacts: {len(artifacts)}")
    print("=" * 80 + "\n")

    return [asdict(a) for a in artifacts]