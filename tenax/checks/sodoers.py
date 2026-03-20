from pathlib import Path

from tenax.utils import (
    get_file_owner,
    get_file_permissions,
    is_file_safe,
    path_exists,
    sha256_file,
)


SUDOERS_PATHS = [
    Path("/etc/sudoers"),
    Path("/etc/sudoers.d"),
]

SUSPICIOUS_KEYWORDS = [
    "NOPASSWD",
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "ALL=(ALL)",
    "ALL=(ALL:ALL)",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
]

SHELL_ESCAPE_BINARIES = [
    "vim",
    "vi",
    "less",
    "more",
    "nano",
    "find",
    "awk",
    "perl",
    "python",
    "python3",
    "ruby",
    "lua",
    "tar",
    "cp",
    "tee",
    "bash",
    "sh",
]


def analyze_sudoers_locations() -> list[dict]:
    findings = []

    for sudoers_path in SUDOERS_PATHS:
        if not path_exists(sudoers_path):
            continue

        if is_file_safe(sudoers_path):
            findings.extend(_analyze_sudoers_file(sudoers_path))
        elif sudoers_path.is_dir():
            for child in _safe_iterdir(sudoers_path):
                if is_file_safe(child):
                    findings.extend(_analyze_sudoers_file(child))

    return findings


def collect_sudoers_locations(hash_files: bool = False) -> list[dict]:
    artifacts = []

    for sudoers_path in SUDOERS_PATHS:
        exists = path_exists(sudoers_path)
        is_file = is_file_safe(sudoers_path)

        artifacts.append(
            {
                "path": str(sudoers_path),
                "type": "sudoers-location",
                "exists": exists,
                "owner": get_file_owner(sudoers_path) if exists else "unknown",
                "permissions": get_file_permissions(sudoers_path) if exists else "unknown",
                "sha256": sha256_file(sudoers_path) if hash_files and exists and is_file else None,
            }
        )

        if exists and sudoers_path.is_dir():
            for child in _safe_iterdir(sudoers_path):
                child_exists = path_exists(child)
                child_is_file = is_file_safe(child)

                artifacts.append(
                    {
                        "path": str(child),
                        "type": "sudoers-artifact",
                        "exists": child_exists,
                        "owner": get_file_owner(child) if child_exists else "unknown",
                        "permissions": get_file_permissions(child) if child_exists else "unknown",
                        "sha256": sha256_file(child) if hash_files and child_exists and child_is_file else None,
                    }
                )

    return artifacts


def _analyze_sudoers_file(path: Path) -> list[dict]:
    findings = []

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (PermissionError, OSError):
        return findings

    score = 0
    reasons = []

    lines = content.splitlines()

    for raw_line in lines:
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in line:
                if keyword == "NOPASSWD":
                    score += 35
                    reasons.append("Contains NOPASSWD rule")
                elif keyword in ("ALL=(ALL)", "ALL=(ALL:ALL)"):
                    score += 25
                    reasons.append(f"Contains broad sudo scope: {keyword}")
                elif keyword in ("/tmp/", "/var/tmp/", "/dev/shm/"):
                    score += 40
                    reasons.append(f"References suspicious execution path: {keyword}")
                else:
                    score += 20
                    reasons.append(f"Contains suspicious keyword: {keyword}")

        for binary in SHELL_ESCAPE_BINARIES:
            if f"/{binary}" in line or f" {binary}" in line:
                score += 15
                reasons.append(f"Permits possible shell-escape binary: {binary}")

        if "*" in line and "ALL" not in line:
            score += 10
            reasons.append("Contains wildcard command allowance")

        if "!" in line and "/bin/sh" in line:
            score += 10
            reasons.append("Attempts selective shell restriction")

    perms = get_file_permissions(path)
    if perms not in ("-r--r-----", "-r--r----", "-r--r-----.", "-r--r-----."):
        score += 10
        reasons.append(f"Unexpected sudoers file permissions: {perms}")

    if path.name.startswith(".") and "/etc/sudoers.d/" in str(path):
        score += 15
        reasons.append("Hidden file in sudoers include directory")

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


def _safe_iterdir(path: Path) -> list[Path]:
    try:
        return list(path.iterdir())
    except (PermissionError, OSError):
        return []


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
