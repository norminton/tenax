from pathlib import Path

from tenax.utils import get_file_owner, get_file_permissions, is_file_safe, path_exists, sha256_file


SSH_FILENAMES = [
    "authorized_keys",
    "known_hosts",
    "config",
]

SUSPICIOUS_KEYWORDS = [
    "command=",
    "from=",
    "permitopen=",
    "environment=",
]


def analyze_ssh_locations() -> list[dict]:
    findings = []

    for home in _get_home_directories():
        ssh_dir = home / ".ssh"

        if not path_exists(ssh_dir) or not ssh_dir.is_dir():
            continue

        for file in _safe_iterdir(ssh_dir):
            if not is_file_safe(file):
                continue

            findings.extend(_analyze_ssh_file(file))

    return findings


def collect_ssh_locations(hash_files: bool = False) -> list[dict]:
    artifacts = []

    for home in _get_home_directories():
        ssh_dir = home / ".ssh"

        exists = path_exists(ssh_dir)

        artifacts.append(
            {
                "path": str(ssh_dir),
                "type": "ssh-directory",
                "exists": exists,
                "owner": get_file_owner(ssh_dir) if exists else "unknown",
                "permissions": get_file_permissions(ssh_dir) if exists else "unknown",
                "sha256": None,
            }
        )

        if not exists or not ssh_dir.is_dir():
            continue

        for file in _safe_iterdir(ssh_dir):
            file_exists = path_exists(file)
            is_file = is_file_safe(file)

            artifacts.append(
                {
                    "path": str(file),
                    "type": "ssh-file",
                    "exists": file_exists,
                    "owner": get_file_owner(file) if file_exists else "unknown",
                    "permissions": get_file_permissions(file) if file_exists else "unknown",
                    "sha256": sha256_file(file) if hash_files and file_exists and is_file else None,
                }
            )

    return artifacts


def _analyze_ssh_file(path: Path) -> list[dict]:
    findings = []

    try:
        content = path.read_text(errors="ignore")
    except (PermissionError, OSError):
        return findings

    score = 0
    reasons = []

    # 🔥 Authorized keys checks
    if path.name == "authorized_keys":
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in content:
                score += 40
                reasons.append(f"Suspicious SSH option: {keyword}")

        # Very long key lines (possible embedded payload)
        for line in content.splitlines():
            if len(line) > 500:
                score += 20
                reasons.append("Unusually long SSH key line")

    # 🔥 Hidden files
    if path.name.startswith("."):
        score += 10
        reasons.append("Hidden file in .ssh directory")

    # 🔥 Bad permissions (SSH is strict)
    perms = get_file_permissions(path)
    if "w" in perms[5:] or "w" in perms[8:]:
        score += 20
        reasons.append("Group/Other write permissions on SSH file")

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


def _safe_iterdir(path: Path) -> list[Path]:
    try:
        return list(path.iterdir())
    except (PermissionError, OSError):
        return []


def _severity_from_score(score: int) -> str:
    if score >= 80:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"
