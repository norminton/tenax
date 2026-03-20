
from pathlib import Path

from tenax.utils import (
    get_file_owner,
    get_file_permissions,
    is_file_safe,
    path_exists,
    sha256_file,
)


CONTAINER_PATHS = [
    Path("/etc/docker"),
    Path("/var/lib/docker/containers"),
    Path("/var/lib/docker/volumes"),
    Path("/etc/containerd"),
    Path("/etc/containers"),
    Path("/var/lib/containers"),
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
    "privileged",
    "cap_add",
    "hostnetwork",
    "hostpid",
    "bind",
]

SUSPICIOUS_FILENAMES = [
    "daemon.json",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "config.v2.json",
    "hostconfig.json",
]


def analyze_container_locations() -> list[dict]:
    findings = []

    for container_path in CONTAINER_PATHS:
        if not path_exists(container_path):
            continue

        if is_file_safe(container_path):
            findings.extend(_analyze_container_file(container_path))
        elif _is_dir_safe(container_path):
            for child in _safe_rglob(container_path):
                if is_file_safe(child):
                    findings.extend(_analyze_container_file(child))

    return findings


def collect_container_locations(hash_files: bool = False) -> list[dict]:
    artifacts = []

    for container_path in CONTAINER_PATHS:
        exists = path_exists(container_path)
        is_file = is_file_safe(container_path)

        artifacts.append(
            {
                "path": str(container_path),
                "type": "container-location",
                "exists": exists,
                "owner": get_file_owner(container_path) if exists else "unknown",
                "permissions": get_file_permissions(container_path) if exists else "unknown",
                "sha256": sha256_file(container_path) if hash_files and exists and is_file else None,
            }
        )

        if exists and _is_dir_safe(container_path):
            for child in _safe_rglob(container_path):
                child_exists = path_exists(child)
                child_is_file = is_file_safe(child)

                artifacts.append(
                    {
                        "path": str(child),
                        "type": "container-artifact",
                        "exists": child_exists,
                        "owner": get_file_owner(child) if child_exists else "unknown",
                        "permissions": get_file_permissions(child) if child_exists else "unknown",
                        "sha256": sha256_file(child) if hash_files and child_exists and child_is_file else None,
                    }
                )

    return artifacts


def _analyze_container_file(path: Path) -> list[dict]:
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

    if path.name in SUSPICIOUS_FILENAMES:
        score += 5
        reasons.append(f"High-value container config file: {path.name}")

    if path.name.startswith("."):
        score += 10
        reasons.append("Hidden container-related file")

    for line in content.splitlines():
        stripped = line.strip()

        if not stripped:
            continue

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in stripped:
                if preview_line is None:
                    preview_line = stripped

                if keyword in ("privileged", "cap_add", "hostnetwork", "hostpid"):
                    score += 30
                    reasons.append(f"Container privilege-related keyword: {keyword}")
                elif keyword in ("/tmp/", "/var/tmp/", "/dev/shm/"):
                    score += 30
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


def _looks_like_network_exec_chain(line: str) -> bool:
    lowered = line.lower()
    has_network = "curl" in lowered or "wget" in lowered
    has_exec = any(x in lowered for x in ("bash", "sh", "python", "perl", "source"))
    return has_network and has_exec


def _safe_rglob(path: Path) -> list[Path]:
    try:
        return list(path.rglob("*"))
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
