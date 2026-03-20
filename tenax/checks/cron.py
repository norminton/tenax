from pathlib import Path

from tenax.utils import get_file_owner, get_file_permissions, path_exists, sha256_file


CRON_PATHS = [
    Path("/etc/crontab"),
    Path("/etc/cron.d"),
    Path("/etc/cron.daily"),
    Path("/etc/cron.hourly"),
    Path("/etc/cron.weekly"),
    Path("/etc/cron.monthly"),
    Path("/var/spool/cron"),
    Path("/var/spool/cron/crontabs"),
]


SUSPICIOUS_KEYWORDS = [
    "curl",
    "wget",
    "nc ",
    "bash -c",
    "sh -c",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "base64",
    "python -c",
    "perl -e",
]


def analyze_cron_locations() -> list[dict]:
    findings = []

    for cron_path in CRON_PATHS:
        if not path_exists(cron_path):
            continue

        if cron_path.is_file():
            findings.extend(_analyze_file(cron_path))
        elif cron_path.is_dir():
            for child in _safe_iterdir(cron_path):
                if child.is_file():
                    findings.extend(_analyze_file(child))

    return findings


def collect_cron_locations(hash_files: bool = False) -> list[dict]:
    artifacts = []

    for cron_path in CRON_PATHS:
        artifact = {
            "path": str(cron_path),
            "type": "cron-location",
            "exists": path_exists(cron_path),
            "owner": get_file_owner(cron_path) if path_exists(cron_path) else "unknown",
            "permissions": get_file_permissions(cron_path) if path_exists(cron_path) else "unknown",
            "sha256": sha256_file(cron_path) if hash_files and cron_path.is_file() and path_exists(cron_path) else None,
        }
        artifacts.append(artifact)

        if path_exists(cron_path) and cron_path.is_dir():
            for child in _safe_iterdir(cron_path):
                artifacts.append(
                    {
                        "path": str(child),
                        "type": "cron-artifact",
                        "exists": True,
                        "owner": get_file_owner(child),
                        "permissions": get_file_permissions(child),
                        "sha256": sha256_file(child) if hash_files and child.is_file() else None,
                    }
                )

    return artifacts


def _analyze_file(path: Path) -> list[dict]:
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

    if path.name.startswith("."):
        score += 10
        reasons.append("Hidden cron file name")

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
