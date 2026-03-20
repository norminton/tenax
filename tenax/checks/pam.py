from pathlib import Path

from tenax.utils import (
    get_file_owner,
    get_file_permissions,
    is_file_safe,
    path_exists,
    sha256_file,
)


PAM_PATHS = [
    Path("/etc/pam.d"),
    Path("/etc/security/pam_env.conf"),
    Path("/etc/security/access.conf"),
]

SUSPICIOUS_KEYWORDS = [
    "pam_exec.so",
    "pam_script",
    "pam_python",
    "pam_permit.so",
    "pam_env.so",
    "pam_unix.so",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "curl",
    "wget",
    "bash -c",
    "sh -c",
    "python -c",
    "perl -e",
]

HIGH_VALUE_KEYWORDS = [
    "pam_exec.so",
    "pam_script",
    "pam_python",
    "pam_permit.so",
]


def analyze_pam_locations() -> list[dict]:
    findings = []

    for pam_path in PAM_PATHS:
        if not path_exists(pam_path):
            continue

        if is_file_safe(pam_path):
            findings.extend(_analyze_pam_file(pam_path))
        elif _is_dir_safe(pam_path):
            for child in _safe_iterdir(pam_path):
                if is_file_safe(child):
                    findings.extend(_analyze_pam_file(child))

    return findings


def collect_pam_locations(hash_files: bool = False) -> list[dict]:
    artifacts = []

    for pam_path in PAM_PATHS:
        exists = path_exists(pam_path)
        is_file = is_file_safe(pam_path)

        artifacts.append(
            {
                "path": str(pam_path),
                "type": "pam-location",
                "exists": exists,
                "owner": get_file_owner(pam_path) if exists else "unknown",
                "permissions": get_file_permissions(pam_path) if exists else "unknown",
                "sha256": sha256_file(pam_path) if hash_files and exists and is_file else None,
            }
        )

        if exists and _is_dir_safe(pam_path):
            for child in _safe_iterdir(pam_path):
                child_exists = path_exists(child)
                child_is_file = is_file_safe(child)

                artifacts.append(
                    {
                        "path": str(child),
                        "type": "pam-artifact",
                        "exists": child_exists,
                        "owner": get_file_owner(child) if child_exists else "unknown",
                        "permissions": get_file_permissions(child) if child_exists else "unknown",
                        "sha256": sha256_file(child) if hash_files and child_exists and child_is_file else None,
                    }
                )

    return artifacts


def _analyze_pam_file(path: Path) -> list[dict]:
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
        score += 15
        reasons.append("Hidden PAM-related file")

    for line in content.splitlines():
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in stripped:
                if preview_line is None:
                    preview_line = stripped

                if keyword in HIGH_VALUE_KEYWORDS:
                    score += 35
                    reasons.append(f"Contains high-risk PAM keyword: {keyword}")
                elif keyword in ("/tmp/", "/var/tmp/", "/dev/shm/"):
                    score += 40
                    reasons.append(f"References suspicious path: {keyword}")
                else:
                    score += 20
                    reasons.append(f"Contains suspicious keyword: {keyword}")

        if _looks_like_network_exec_chain(stripped):
            if preview_line is None:
                preview_line = stripped
            score += 40
            reasons.append("Contains likely download-and-execute chain")

    perms = get_file_permissions(path)
    if "w" in perms[5:] or "w" in perms[8:]:
        score += 15
        reasons.append("Group/Other write permissions on PAM file")

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