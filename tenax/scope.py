from __future__ import annotations

import importlib
import posixpath
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterator

try:
    import pwd
except ImportError:  # pragma: no cover
    pwd = None  # type: ignore[assignment]


MODULE_PATH_SPECS: dict[str, dict[str, object]] = {
    "cron": {
        "constant": "CRON_PATHS",
        "system_paths": [
            "/etc/crontab",
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
            "/var/spool/cron",
            "/var/spool/cron/crontabs",
        ],
    },
    "systemd": {
        "constant": "SYSTEMD_PATHS",
        "system_paths": [
            "/etc/systemd/system",
            "/lib/systemd/system",
            "/usr/lib/systemd/system",
            "/run/systemd/system",
            "/etc/systemd/user",
            "/usr/lib/systemd/user",
        ],
        "user_suffixes": [".config/systemd/user"],
    },
    "shell_profiles": {
        "constant": "SHELL_PROFILE_PATHS",
        "system_paths": [
            "/etc/profile",
            "/etc/bash.bashrc",
            "/etc/zsh/zshrc",
            "/etc/zshrc",
            "/etc/profile.d",
            "/etc/skel/.bashrc",
            "/etc/skel/.profile",
            "/etc/skel/.zshrc",
        ],
        "user_suffixes": [".bashrc", ".bash_profile", ".profile", ".zprofile", ".zshrc"],
    },
    "ssh": {
        "constant": "SSH_PATHS",
        "system_paths": ["/etc/ssh"],
        "user_suffixes": [".ssh"],
    },
    "sudoers": {
        "constant": "SUDOERS_PATHS",
        "system_paths": ["/etc/sudoers", "/etc/sudoers.d"],
    },
    "rc_init": {
        "constant": "RC_PATHS",
        "system_paths": ["/etc/init.d", "/etc/rc.d", "/etc/rc.local"],
    },
    "tmp_paths": {
        "constant": "TMP_PATHS",
        "system_paths": ["/tmp", "/var/tmp", "/dev/shm", "/run/shm"],
    },
    "ld_preload": {
        "constant": "LD_PRELOAD_PATHS",
        "system_paths": ["/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d"],
        "user_suffixes": [".bashrc", ".profile", ".zshrc"],
    },
    "autostart_hooks": {
        "constant": "AUTOSTART_PATHS",
        "system_paths": ["/etc/xdg/autostart", "/usr/share/autostart"],
        "user_suffixes": [".config/autostart"],
    },
    "network_hooks": {
        "constant": "NETWORK_HOOK_PATHS",
        "system_paths": [
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
        ],
        "user_suffixes": [".config/NetworkManager"],
    },
    "pam": {
        "constant": "PAM_PATHS",
        "system_paths": ["/etc/pam.d"],
    },
    "at_jobs": {
        "constant": "AT_JOB_PATHS",
        "system_paths": ["/var/spool/cron/atjobs", "/var/spool/at", "/var/spool/atjobs"],
    },
    "containers": {
        "constant": "CONTAINER_PATHS",
        "system_paths": [
            "/etc/docker",
            "/etc/containers",
            "/var/lib/docker/containers",
            "/var/lib/containers",
            "/usr/share/containers",
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
        ],
        "user_suffixes": [".config/containers", ".docker"],
    },
    "environment_hooks": {
        "constant": "ENVIRONMENT_HOOK_PATHS",
        "system_paths": [
            "/etc/profile",
            "/etc/environment",
            "/etc/bash.bashrc",
            "/etc/profile.d",
            "/etc/zsh/zshrc",
            "/etc/zshrc",
        ],
        "user_suffixes": [".bashrc", ".bash_profile", ".profile", ".zshrc"],
    },
    "capabilities": {
        "constant": "CAPABILITY_SCAN_PATHS",
        "system_paths": ["/usr/bin", "/usr/sbin", "/bin", "/sbin"],
    },
}

MODULE_IMPORT_PATHS = {
    module_name: f"tenax.checks.{module_name}"
    for module_name in MODULE_PATH_SPECS
}


@dataclass(frozen=True)
class TargetUser:
    username: str
    home: str
    source: str


@dataclass(frozen=True)
class ScanScope:
    root_prefix: Path | None
    target_users: tuple[TargetUser, ...]

    @property
    def root_label(self) -> str:
        return "/" if self.root_prefix else "live-host:/"

    def resolve_host_path(self, path_value: str | Path) -> Path:
        normalized = normalize_path_string(path_value)
        if normalized.startswith("/") and self.root_prefix:
            relative = PurePosixPath(normalized).relative_to(PurePosixPath("/"))
            return self.root_prefix.joinpath(*relative.parts)
        return Path(normalized)

    def target_path_from_host(self, path_value: str | Path | None) -> str | None:
        if path_value is None:
            return None

        normalized = normalize_path_string(path_value)
        if not self.root_prefix:
            return normalized

        host_path = Path(str(path_value))
        root_prefix = self.root_prefix
        try:
            relative = host_path.relative_to(root_prefix)
        except ValueError:
            return normalized

        posix_relative = PurePosixPath(*relative.parts)
        return f"/{posix_relative.as_posix()}" if posix_relative.parts else "/"


def normalize_path_string(path_value: str | Path | None) -> str:
    if path_value is None:
        return ""

    raw = str(path_value).strip()
    if not raw:
        return ""

    if raw.startswith("/"):
        normalized = posixpath.normpath(raw)
        return "/" if normalized == "." else normalized

    return str(Path(raw).expanduser())


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    deduped: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped


def _parse_passwd_users(scope: ScanScope) -> list[TargetUser]:
    passwd_path = scope.resolve_host_path("/etc/passwd")
    if not passwd_path.is_file():
        return []

    users: list[TargetUser] = []
    try:
        for raw_line in passwd_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not raw_line or raw_line.startswith("#"):
                continue
            parts = raw_line.split(":")
            if len(parts) < 7:
                continue
            username = parts[0].strip()
            home = normalize_path_string(parts[5].strip())
            if not username or not home.startswith("/"):
                continue
            users.append(TargetUser(username=username, home=home, source="passwd"))
    except OSError:
        return []
    return users


def _discover_home_dirs(scope: ScanScope) -> list[TargetUser]:
    users: list[TargetUser] = []
    home_root = scope.resolve_host_path("/home")
    if home_root.is_dir():
        try:
            for child in sorted(home_root.iterdir(), key=lambda item: item.name.lower()):
                if child.is_dir():
                    users.append(TargetUser(username=child.name, home=f"/home/{child.name}", source="home_dir"))
        except OSError:
            pass

    root_home = scope.resolve_host_path("/root")
    if root_home.is_dir():
        users.append(TargetUser(username="root", home="/root", source="root_dir"))
    return users


def discover_target_users(root_prefix: Path | None = None) -> tuple[TargetUser, ...]:
    preliminary_scope = ScanScope(root_prefix=root_prefix, target_users=())
    discovered = _parse_passwd_users(preliminary_scope)

    if not discovered and pwd is not None and root_prefix is None:
        try:
            for entry in pwd.getpwall():
                home = normalize_path_string(entry.pw_dir)
                if home.startswith("/"):
                    discovered.append(TargetUser(username=entry.pw_name, home=home, source="pwd"))
        except Exception:  # pragma: no cover
            pass

    discovered.extend(_discover_home_dirs(preliminary_scope))

    deduped: dict[str, TargetUser] = {}
    for user in discovered:
        home = normalize_path_string(user.home)
        if not home.startswith("/"):
            continue
        host_home = preliminary_scope.resolve_host_path(home)
        if user.username != "root" and not host_home.exists():
            continue
        deduped.setdefault(home, TargetUser(username=user.username, home=home, source=user.source))

    if "/root" not in deduped:
        deduped["/root"] = TargetUser(username="root", home="/root", source="implicit_root")

    return tuple(sorted(deduped.values(), key=lambda item: (item.home != "/root", item.home)))


def build_scan_scope(root_prefix: str | Path | None = None) -> ScanScope:
    scope_root = None
    if root_prefix:
        scope_root = Path(root_prefix).expanduser().resolve(strict=False)
    users = discover_target_users(scope_root)
    return ScanScope(root_prefix=scope_root, target_users=users)


def build_module_paths(module_name: str, scope: ScanScope) -> list[Path]:
    spec = MODULE_PATH_SPECS.get(module_name)
    if spec is None:
        return []

    paths: list[Path] = []
    for raw_path in spec.get("system_paths", []):
        paths.append(scope.resolve_host_path(str(raw_path)))

    user_suffixes = [str(item) for item in spec.get("user_suffixes", [])]
    for user in scope.target_users:
        user_home = PurePosixPath(user.home)
        for suffix in user_suffixes:
            relative = PurePosixPath(suffix)
            target_path = str(user_home / relative)
            paths.append(scope.resolve_host_path(target_path))

    return _dedupe_paths(paths)


def build_watched_location_paths(module_names: list[str], scope: ScanScope) -> dict[str, list[str]]:
    watched: dict[str, list[str]] = {}
    for module_name in module_names:
        watched[module_name] = [
            scope.target_path_from_host(path) or str(path)
            for path in build_module_paths(module_name, scope)
        ]
    return watched


@contextmanager
def apply_module_scope(module_names: list[str], scope: ScanScope) -> Iterator[None]:
    original_values: list[tuple[object, str, object]] = []
    try:
        for module_name in module_names:
            spec = MODULE_PATH_SPECS.get(module_name)
            if spec is None:
                continue
            module = importlib.import_module(MODULE_IMPORT_PATHS[module_name])
            constant_name = str(spec["constant"])
            if not hasattr(module, constant_name):
                continue
            original_values.append((module, constant_name, getattr(module, constant_name)))
            setattr(module, constant_name, build_module_paths(module_name, scope))
        yield
    finally:
        for module, constant_name, original_value in reversed(original_values):
            setattr(module, constant_name, original_value)
