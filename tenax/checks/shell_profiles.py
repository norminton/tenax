from pathlib import Path

from tenax.utils import (
    get_file_owner,
    get_file_permissions,
    is_file_safe,
    path_exists,
    sha256_file,
)


SYSTEM_PROFILE_PATHS = [
    Path("/etc/profile"),
    Path("/etc/profile.d"),
    Path("/etc/bash.bashrc"),
    Path("/etc/environment"),
]

USER_PROFILE_FILENAMES = [
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zlogin",
    ".zprofile",
]


SUSPICIOUS_KEYWORDS = [
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
]


def analyze_shell_profile_locations() -> list[dict]:
    findings = []

    for profile_path in SYSTEM_PROFILE_PATHS:
        if not path_exists(profile_path):
            continue

        if is_file_safe(profile_path):
            findings.extend(_analyze_profile_file(profile_path))
        elif profile_path.is_dir():
            for child in _safe_iterdir(profile_path):
                if is_file_safe(child):
                    findings.extend(_analyze_profile_file(child))

    for user_home in _get_home_directories():
        for filename in USER_PROFILE_FILENAMES:
            candidate = user_home / filename
            if path_exists(candidate) and is_file_safe(candidate):
                findings.extend(_analyze_profile_file(candidate))

    return findings


def collect_shell_profile_locations(hash_files: bool = False) -> list[dict]:
    artifacts = []

    for profile_path in SYSTEM_PROFILE_PATHS:
        exists = path_exists(profile_path)
        is_file = is_file_safe(profile_path)

        artifacts.append(
            {
                "path": str(profile_path),
                "type": "shell-profile-location",
                "exists": exists,
                "owner": get_file_owner(profile_path) if exists else "unknown",
                "permissions": get_file_permissions(profile_path) if exists else "unknown",
                "sha256": sha256_file(profile_path) if hash_files and exists and is_file else None,
            }
        )

        if exists and profile_path.is_dir():
            for child in _safe_iterdir(profile_path):
                child_exists = path_exists(child)
                child_is_file = is_file_safe(child)

                artifacts.append(
                    {
                        "path": str(child),
                        "type": "shell-profile-artifact",
                        "exists": child_exists,
                        "owner": get_file_owner(child) if child_exists else "unknown",
                        "permissions": get_file_permissions(child) if child_exists else "unknown",
                        "sha256": sha256_file(child) if hash_files and child_exists and child_is_file else None,
                    }
                )

    for user_home in _get_home_directories():
        for filename in USER_PROFILE_FILENAMES:
            candidate = user_home / filename
            exists = path_exists(candidate)
            is_file = is_file_safe(candidate)

            artifacts.append(
                {
                    "path": str(candidate),
                    "type": "user-shell-profile",
                    "exists": exists,
                    "owner": get_file_owner(candidate) if exists else "unknown",
                    "permissions": get_file_permissions(candidate) if exists else "unknown",
                    "sha256": sha256_file(candidate) if hash_files and exists and is_file else None,
                }
            )

    return artifacts


def _analyze_profile_file(path: Path) -> list[dict]:
    findings = []

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (PermissionError, OSError):
        return findings

    score = 0
    reasons = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in content:
            score += 20
            reasons.append(f"Contains suspicious keyword: {keyword}")

    if "export LD_PRELOAD=" in content or "LD_PRELOAD=" in content:
        score += 40
        reasons.append("Sets LD_PRELOAD in startup file")

    if "alias sudo=" in content or "function sudo()" in content:
        score += 30
        reasons.append("Overrides sudo behavior")

    if "PROMPT_COMMAND=" in content:
        score += 15
        reasons.append("Uses PROMPT_COMMAND in startup file")

    if path.name.startswith(".") and "/etc/" not in str(path):
        score += 5
        reasons.append("User hidden startup file")

    if _contains_network_execution_chain(content):
        score += 40
        reasons.append("Contains likely download-and-execute chain")

    if score > 0:
        findings.append(
            {
                "path": str(path),
                "score": score,
                "severity": _severity_from_score(score),
                "reason": "; ".join(reasons),
            }
        )

    return findings


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


def _severity_from_score(score: int) -> str:
    if score >= 80:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"


def _safe_iterdir(path: Path) -> list[Path]:
    try:
        return list(path.iterdir())
    except (PermissionError, OSError):
        return []
