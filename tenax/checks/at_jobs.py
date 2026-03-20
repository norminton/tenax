from pathlib import Path

from tenax.utils import (
    get_file_owner,
    get_file_permissions,
    is_file_safe,
    path_exists,
    sha256_file,
)


AT_JOB_PATHS = [
    Path("/var/spool/at"),
    Path("/var/spool/cron/atjobs"),
    Path("/var/spool/cron/atspool"),
]

SUSPICIOUS_KEYWORDS = [
    "curl",
    "wget",
    "nc ",
    "ncat",
    "bash -c",
    "sh -c",
    "python -c",
    "perl -e",
    "base64",
    "nohup",
    "setsid",
    "socat",
    "mkfifo",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/dev/tcp/",
]

SUSPICIOUS_NAMES = [
    "update",
    "backup",
    "dbus",
    "network",
    "system",
    "job",
]


def analyze_at_job_locations() -> list[dict]:
    findings = []

    for at_path in AT_JOB_PATHS:
        if not path_exists(at_path):
            continue

        if is_file_safe(at_path):
            findings.extend(_analyze_at_file(at_path))
        elif _is_dir_safe(at_path):
            for child in _safe_iterdir(at_path):
                if is_file_safe(child):
                    findings.extend(_analyze_at_file(child))

    return findings


def collect_at_job_locations(hash_files: bool = False) -> list[dict]:
    artifacts = []

    for at_path in AT_JOB_PATHS:
        exists = path_exists(at_path)
        is_file = is_file_safe(at_path)

        artifacts.append(
            {
                "path": str(at_path),
                "type": "at-job-location",
                "exists": exists,
                "owner": get_file_owner(at_path) if exists else "unknown",
                "permissions": get_file_permissions(at_path) if exists else "unknown",
                "sha256": sha256_file(at_path) if hash_files and exists and is_file else None,
            }
        )

        if exists and _is_dir_safe(at_path):
            for child in _safe_iterdir(at_path):
                child_exists = path_exists(child)
                child_is_file = is_file_safe(child)

                artifacts.append(
                    {
                        "path": str(child),
                        "type": "at-job-artifact",
                        "exists": child_exists,
                        "owner": get_file_owner(child) if child_exists else "unknown",
                        "permissions": get_file_permissions(child) if child_exists else "unknown",
                        "sha256": sha256_file(child) if hash_files and child_exists and child_is_file else None,
                    }
                )

    return artifacts


def _analyze_at_file(path: Path) -> list[dict]:
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

    name_lower = path.name.lower()
    for bad_name in SUSPICIOUS_NAMES:
        if bad_name in name_lower:
            score += 10
            reasons.append(f"Suspicious at-job name pattern: {bad_name}")

    if path.name.startswith("."):
        score += 15
        reasons.append("Hidden at-job file")

    for line in content.splitlines():
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in stripped:
                if preview_line is None:
                    preview_line = stripped
                score += 20
                reasons.append(f"Contains suspicious keyword: {keyword}")

        if _looks_like_network_exec_chain(stripped):
            if preview_line is None:
                preview_line = stripped
            score += 40
            reasons.append("Contains likely download-and-execute chain")

    perms = get_file_permissions(path)
    if "x" in perms:
        score += 10
        reasons.append("Executable permissions on at-job file")

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