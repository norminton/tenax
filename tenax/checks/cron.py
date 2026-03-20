from pathlib import Path

from tenax.utils import get_file_owner, get_file_permissions, is_file_safe, path_exists, sha256_file


CRON_PATHS = [
    Path("/etc/crontab"),
    Path("/etc/cron.d"),
    Path("/var/spool/cron"),
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
]


def analyze_cron_locations() -> list[dict]:
    findings = []

    for cron_path in CRON_PATHS:
        if not path_exists(cron_path):
            continue

        if is_file_safe(cron_path):
            findings.extend(_analyze_cron_file(cron_path))
        elif cron_path.is_dir():
            for child in _safe_iterdir(cron_path):
                if is_file_safe(child):
                    findings.extend(_analyze_cron_file(child))

    return findings


def collect_cron_locations(hash_files: bool = False) -> list[dict]:
    artifacts = []

    for cron_path in CRON_PATHS:
        exists = path_exists(cron_path)
        is_file = is_file_safe(cron_path)

        artifacts.append(
            {
                "path": str(cron_path),
                "type": "cron-location",
                "exists": exists,
                "owner": get_file_owner(cron_path) if exists else "unknown",
                "permissions": get_file_permissions(cron_path) if exists else "unknown",
                "sha256": sha256_file(cron_path) if hash_files and exists and is_file else None,
            }
        )

        if exists and cron_path.is_dir():
            for child in _safe_iterdir(cron_path):
                artifacts.append(
                    {
                        "path": str(child),
                        "type": "cron-artifact",
                        "exists": True,
                        "owner": get_file_owner(child),
                        "permissions": get_file_permissions(child),
                        "sha256": sha256_file(child) if hash_files else None,
                    }
                )

    return artifacts


def _analyze_cron_file(path: Path) -> list[dict]:
    findings = []

    try:
        content = path.read_text(errors="ignore")
    except (PermissionError, OSError):
        return findings

    score = 0
    reasons = []
    preview_line = None

    for line in content.splitlines():
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in stripped:
                if preview_line is None:
                    preview_line = stripped
                score += 25
                reasons.append(f"Contains suspicious keyword: {keyword}")

    if score > 0:
        findings.append(
            {
                "path": str(path),
                "score": score,
                "severity": _severity(score),
                "reason": "; ".join(set(reasons)),
                "preview": preview_line,
            }
        )

    return findings


def _safe_iterdir(path):
    try:
        return list(path.iterdir())
    except:
        return []


def _severity(score):
    if score >= 80:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"