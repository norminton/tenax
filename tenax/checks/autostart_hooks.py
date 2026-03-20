from pathlib import Path

from tenax.utils import (
    get_file_owner,
    get_file_permissions,
    is_file_safe,
    path_exists,
    sha256_file,
)


SYSTEM_AUTOSTART_PATHS = [
    Path("/etc/xdg/autostart"),
]

USER_RELATIVE_PATHS = [
    ".config/autostart",
    ".config/systemd/user",
    ".config/environment.d",
    ".pam_environment",
]

SUSPICIOUS_KEYWORDS = [
    "Exec=",
    "Hidden=true",
    "X-GNOME-Autostart-enabled=true",
    "curl",
    "wget",
    "nc ",
    "bash -c",
    "sh -c",
    "python -c",
    "perl -e",
    "base64",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "nohup",
    "setsid",
    "socat",
    "mkfifo",
    "LD_PRELOAD",
]

SUSPICIOUS_NAMES = [
    "update",
    "backup",
    "dbus",
    "network",
    "system",
    "sysinit",
    "kworker",
    "gnome-update",
    "session-update",
]


def analyze_autostart_hook_locations() -> list[dict]:
    findings = []

    for target_path in SYSTEM_AUTOSTART_PATHS:
        if not path_exists(target_path):
            continue

        if target_path.is_dir():
            for child in _safe_rglob(target_path):
                if is_file_safe(child):
                    findings.extend(_analyze_hook_file(child))
        elif is_file_safe(target_path):
            findings.extend(_analyze_hook_file(target_path))

    for user_home in _get_home_directories():
        for relative in USER_RELATIVE_PATHS:
            candidate = user_home / relative

            if not path_exists(candidate):
                continue

            if candidate.is_dir():
                for child in _safe_rglob(candidate):
                    if is_file_safe(child):
                        findings.extend(_analyze_hook_file(child))
            elif is_file_safe(candidate):
                findings.extend(_analyze_hook_file(candidate))

    return findings


def collect_autostart_hook_locations(hash_files: bool = False) -> list[dict]:
    artifacts = []

    for target_path in SYSTEM_AUTOSTART_PATHS:
        exists = path_exists(target_path)
        is_file = is_file_safe(target_path)

        artifacts.append(
            {
                "path": str(target_path),
                "type": "autostart-location",
                "exists": exists,
                "owner": get_file_owner(target_path) if exists else "unknown",
                "permissions": get_file_permissions(target_path) if exists else "unknown",
                "sha256": sha256_file(target_path) if hash_files and exists and is_file else None,
            }
        )

        if exists and target_path.is_dir():
            for child in _safe_rglob(target_path):
                child_exists = path_exists(child)
                child_is_file = is_file_safe(child)

                artifacts.append(
                    {
                        "path": str(child),
                        "type": "autostart-artifact",
                        "exists": child_exists,
                        "owner": get_file_owner(child) if child_exists else "unknown",
                        "permissions": get_file_permissions(child) if child_exists else "unknown",
                        "sha256": sha256_file(child) if hash_files and child_exists and child_is_file else None,
                    }
                )

    for user_home in _get_home_directories():
        for relative in USER_RELATIVE_PATHS:
            candidate = user_home / relative
            exists = path_exists(candidate)
            is_file = is_file_safe(candidate)

            artifacts.append(
                {
                    "path": str(candidate),
                    "type": "user-autostart-location",
                    "exists": exists,
                    "owner": get_file_owner(candidate) if exists else "unknown",
                    "permissions": get_file_permissions(candidate) if exists else "unknown",
                    "sha256": sha256_file(candidate) if hash_files and exists and is_file else None,
                }
            )

            if exists and candidate.is_dir():
                for child in _safe_rglob(candidate):
                    child_exists = path_exists(child)
                    child_is_file = is_file_safe(child)

                    artifacts.append(
                        {
                            "path": str(child),
                            "type": "user-autostart-artifact",
                            "exists": child_exists,
                            "owner": get_file_owner(child) if child_exists else "unknown",
                            "permissions": get_file_permissions(child) if child_exists else "unknown",
                            "sha256": sha256_file(child) if hash_files and child_exists and child_is_file else None,
                        }
                    )

    return artifacts


def _analyze_hook_file(path: Path) -> list[dict]:
    findings = []

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except PermissionError:
        findings.append(
            {
                "path": str(path),
                "score": 0,
                "severity": "INFO",
                "reason": "File exists but could not be read due to permissions",
            }
        )
        return findings
    except OSError:
        return findings

    score = 0
    reasons = []

    name_lower = path.name.lower()

    for bad_name in SUSPICIOUS_NAMES:
        if bad_name in name_lower:
            score += 10
            reasons.append(f"Suspicious autostart file name pattern: {bad_name}")

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in content:
            if keyword == "Exec=":
                continue
            score += 20
            reasons.append(f"Contains suspicious keyword: {keyword}")

    if "Exec=" in content:
        exec_value = _extract_exec_value(content)
        if exec_value:
            if exec_value.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
                score += 40
                reasons.append(f"Exec launches from suspicious path: {exec_value}")
            elif exec_value.startswith("/home/"):
                score += 20
                reasons.append(f"Exec launches from user-writable path: {exec_value}")

    if "Hidden=true" in content:
        score += 15
        reasons.append("Desktop entry marked hidden")

    if "LD_PRELOAD=" in content:
        score += 40
        reasons.append("Sets LD_PRELOAD in login hook")

    if path.suffix == ".desktop":
        score += 10
        reasons.append("Desktop autostart entry present")

    if path.name.startswith("."):
        score += 15
        reasons.append("Hidden file in autostart path")

    if _contains_network_execution_chain(content):
        score += 40
        reasons.append("Contains likely download-and-execute chain")

    perms = get_file_permissions(path)
    if "w" in perms[5:] or "w" in perms[8:]:
        score += 15
        reasons.append("Group/Other write permissions on autostart file")

    if score > 0:
        findings.append(
            {
                "path": str(path),
                "score": score,
                "severity": _severity_from_score(score),
                "reason": "; ".join(_dedupe(reasons)),
            }
        )

    return findings


def _extract_exec_value(content: str) -> str | None:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("Exec="):
            return stripped.split("=", 1)[1].strip()
    return None


def _contains_network_execution_chain(content: str) -> bool:
    lowered = content.lower()
    network_terms = ["curl", "wget"]
    exec_terms = ["bash", "sh", "source", "python", "perl"]

    return any(n in lowered for n in network_terms) and any(e in lowered for e in exec_terms)


def _get_home_directories() -> list[Path]:
    homes = []

    base_paths = [Path("/home"), Path("/root")]

    for base in base_paths:
        if not path_exists(base):
            continue

        if base == Path("/root"):
            homes.append(base)
            continue

        try:
            for child in base.iterdir():
                if child.is_dir():
                    homes.append(child)
        except (PermissionError, OSError):
            continue

    return homes


def _safe_rglob(base: Path) -> list[Path]:
    results = []

    try:
        for child in base.rglob("*"):
            results.append(child)
    except (PermissionError, OSError):
        pass

    return results


def _dedupe(items: list[str]) -> list[str]:
    seen = set()
    ordered = []

    for item in items:
        if item not in seen:
            seen.add(item)
            ordered.append(item)

    return ordered


def _severity_from_score(score: int) -> str:
    if score >= 80:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"