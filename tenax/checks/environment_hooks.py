from pathlib import Path

from tenax.utils import (
    get_file_owner,
    get_file_permissions,
    is_file_safe,
    path_exists,
    sha256_file,
)


ENVIRONMENT_PATHS = [
    Path("/etc/environment"),
    Path("/etc/environment.d"),
    Path("/etc/security/pam_env.conf"),
]

USER_ENVIRONMENT_FILES = [
    ".pam_environment",
    ".config/environment.d",
]

SUSPICIOUS_KEYWORDS = [
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "PATH=",
    "PYTHONPATH",
    "PROMPT_COMMAND",
    "BASH_ENV",
    "ENV=",
    "curl",
    "wget",
    "bash -c",
    "sh -c",
    "python -c",
    "perl -e",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
]


def analyze_environment_hook_locations() -> list[dict]:
    findings = []

    for env_path in ENVIRONMENT_PATHS:
        if not path_exists(env_path):
            continue

        if is_file_safe(env_path):
            findings.extend(_analyze_environment_file(env_path))
        elif _is_dir_safe(env_path):
            for child in _safe_iterdir(env_path):
                if is_file_safe(child):
                    findings.extend(_analyze_environment_file(child))

    for user_home in _get_home_directories():
        for rel_path in USER_ENVIRONMENT_FILES:
            candidate = user_home / rel_path

            if not path_exists(candidate):
                continue

            if is_file_safe(candidate):
                findings.extend(_analyze_environment_file(candidate))
            elif _is_dir_safe(candidate):
                for child in _safe_iterdir(candidate):
                    if is_file_safe(child):
                        findings.extend(_analyze_environment_file(child))

    return findings


def collect_environment_hook_locations(hash_files: bool = False) -> list[dict]:
    artifacts = []

    for env_path in ENVIRONMENT_PATHS:
        exists = path_exists(env_path)
        is_file = is_file_safe(env_path)

        artifacts.append(
            {
                "path": str(env_path),
                "type": "environment-hook-location",
                "exists": exists,
                "owner": get_file_owner(env_path) if exists else "unknown",
                "permissions": get_file_permissions(env_path) if exists else "unknown",
                "sha256": sha256_file(env_path) if hash_files and exists and is_file else None,
            }
        )

        if exists and _is_dir_safe(env_path):
            for child in _safe_iterdir(env_path):
                child_exists = path_exists(child)
                child_is_file = is_file_safe(child)

                artifacts.append(
                    {
                        "path": str(child),
                        "type": "environment-hook-artifact",
                        "exists": child_exists,
                        "owner": get_file_owner(child) if child_exists else "unknown",
                        "permissions": get_file_permissions(child) if child_exists else "unknown",
                        "sha256": sha256_file(child) if hash_files and child_exists and child_is_file else None,
                    }
                )

    for user_home in _get_home_directories():
        for rel_path in USER_ENVIRONMENT_FILES:
            candidate = user_home / rel_path
            exists = path_exists(candidate)
            is_file = is_file_safe(candidate)

            artifacts.append(
                {
                    "path": str(candidate),
                    "type": "user-environment-hook-location",
                    "exists": exists,
                    "owner": get_file_owner(candidate) if exists else "unknown",
                    "permissions": get_file_permissions(candidate) if exists else "unknown",
                    "sha256": sha256_file(candidate) if hash_files and exists and is_file else None,
                }
            )

            if exists and _is_dir_safe(candidate):
                for child in _safe_iterdir(candidate):
                    child_exists = path_exists(child)
                    child_is_file = is_file_safe(child)

                    artifacts.append(
                        {
                            "path": str(child),
                            "type": "user-environment-hook-artifact",
                            "exists": child_exists,
                            "owner": get_file_owner(child) if child_exists else "unknown",
                            "permissions": get_file_permissions(child) if child_exists else "unknown",
                            "sha256": sha256_file(child) if hash_files and child_exists and child_is_file else None,
                        }
                    )

    return artifacts


def _analyze_environment_file(path: Path) -> list[dict]:
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
                "preview": "<unreadable due to permissions>",
            }
        )
        return findings
    except OSError:
        return findings

    score = 0
    reasons = []
    preview_line = None

    if path.name.startswith("."):
        score += 10
        reasons.append("Hidden environment-related file")

    for line in content.splitlines():
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in stripped:
                if preview_line is None:
                    preview_line = stripped

                if keyword in ("LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "PYTHONPATH"):
                    score += 35
                    reasons.append(f"Environment injection keyword: {keyword}")
                elif keyword == "PATH=":
                    score += 15
                    reasons.append("PATH modified in environment file")
                elif keyword in ("/tmp/", "/var/tmp/", "/dev/shm/"):
                    score += 35
                    reasons.append(f"References suspicious path: {keyword}")
                else:
                    score += 20
                    reasons.append(f"Contains suspicious keyword: {keyword}")

        if _looks_like_network_exec_chain(stripped):
            if preview_line is None:
                preview_line = stripped
            score += 40
            reasons.append("Contains likely download-and-execute chain")

    if score > 0:
        findings.append(
            {
                "path": str(path),
                "score": score,
                "severity": _severity_from_score(score),
                "reason": "; ".join(_dedupe(reasons)),
                "preview": preview_line,
            }
        )

    return findings


def _get_home_directories() -> list[Path]:
    homes = []

    for base in [Path("/home"), Path("/root")]:
        if not path_exists(base):
            continue

        if str(base) == "/root":
            homes.append(base)
            continue

        try:
            for child in base.iterdir():
                if _is_dir_safe(child):
                    homes.append(child)
        except (PermissionError, OSError):
            continue

    return homes


def _looks_like_network_exec_chain(line: str) -> bool:
    lowered = line.lower()
    has_network = "curl" in lowered or "wget" in lowered
    has_exec = any(x in lowered for x in ("bash", "sh", "python", "perl", "source"))
    return has_network and has_exec


def _safe_iterdir(path: Path) -> list[Path]:
    try:
        return list(path.iterdir())
    except (PermissionError, OSError):
        return []


def _is_dir_safe(path: Path) -> bool:
    try:
        return path.is_dir()
    except (PermissionError, OSError):
        return False


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