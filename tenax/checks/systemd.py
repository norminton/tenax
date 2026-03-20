from pathlib import Path

from tenax.utils import get_file_owner, get_file_permissions, path_exists, sha256_file


SYSTEMD_PATHS = [
    Path("/etc/systemd/system"),
    Path("/lib/systemd/system"),
    Path("/usr/lib/systemd/system"),
    Path("/run/systemd/system"),
]

SUSPICIOUS_KEYWORDS = [
    "ExecStart=",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "curl",
    "wget",
    "nc ",
    "bash -c",
    "sh -c",
    "python -c",
    "perl -e",
    "base64",
]

SUSPICIOUS_SERVICE_NAMES = [
    "update",
    "backup",
    "systemd-update",
    "network-update",
    "dbus-update",
    "kworker",
    "sysinit",
]


def analyze_systemd_locations() -> list[dict]:
    findings = []

    for systemd_path in SYSTEMD_PATHS:
        if not path_exists(systemd_path) or not systemd_path.is_dir():
            continue

        for child in _safe_rglob(systemd_path, "*.service"):
            if child.is_file():
                findings.extend(_analyze_unit_file(child))

    return findings


def collect_systemd_locations(hash_files: bool = False) -> list[dict]:
    artifacts = []

    for systemd_path in SYSTEMD_PATHS:
        artifacts.append(
            {
                "path": str(systemd_path),
                "type": "systemd-location",
                "exists": path_exists(systemd_path),
                "owner": get_file_owner(systemd_path) if path_exists(systemd_path) else "unknown",
                "permissions": get_file_permissions(systemd_path) if path_exists(systemd_path) else "unknown",
                "sha256": None,
            }
        )

        if not path_exists(systemd_path) or not systemd_path.is_dir():
            continue

        for child in _safe_rglob(systemd_path, "*.service"):
            artifacts.append(
                {
                    "path": str(child),
                    "type": "systemd-unit",
                    "exists": True,
                    "owner": get_file_owner(child),
                    "permissions": get_file_permissions(child),
                    "sha256": sha256_file(child) if hash_files else None,
                }
            )

    return artifacts


def _analyze_unit_file(path: Path) -> list[dict]:
    findings = []

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (PermissionError, OSError):
        return findings

    score = 0
    reasons = []

    name_lower = path.name.lower()

    for bad_name in SUSPICIOUS_SERVICE_NAMES:
        if bad_name in name_lower:
            score += 10
            reasons.append(f"Suspicious service name pattern: {bad_name}")

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in content:
            if keyword == "ExecStart=":
                continue
            score += 20
            reasons.append(f"Contains suspicious keyword: {keyword}")

    if "ExecStart=" not in content:
        score += 10
        reasons.append("Missing ExecStart directive")

    exec_path = _extract_execstart(content)
    if exec_path:
        if exec_path.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
            score += 40
            reasons.append(f"ExecStart launches from suspicious path: {exec_path}")

        if exec_path.startswith("/home/"):
            score += 20
            reasons.append(f"ExecStart launches from user-writable area: {exec_path}")

    if path.name.startswith("."):
        score += 15
        reasons.append("Hidden systemd unit name")

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


def _extract_execstart(content: str) -> str | None:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("ExecStart="):
            return stripped.split("=", 1)[1].strip()
    return None


def _severity_from_score(score: int) -> str:
    if score >= 80:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"


def _safe_rglob(base: Path, pattern: str) -> list[Path]:
    try:
        return list(base.rglob(pattern))
    except (PermissionError, OSError):
        return []
