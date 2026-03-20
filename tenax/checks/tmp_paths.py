from pathlib import Path

from tenax.utils import (
    get_file_owner,
    get_file_permissions,
    is_file_safe,
    path_exists,
    sha256_file,
)


TMP_PATHS = [
    Path("/tmp"),
    Path("/var/tmp"),
    Path("/dev/shm"),
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
    "/dev/tcp/",
]

SUSPICIOUS_NAMES = [
    "update",
    "backup",
    "dbus",
    "network",
    "system",
    "sysinit",
    "kworker",
    "cron",
    "ssh",
]


def analyze_tmp_paths() -> list[dict]:
    findings = []

    for tmp_path in TMP_PATHS:
        if not path_exists(tmp_path) or not tmp_path.is_dir():
            continue

        for child in _safe_rglob(tmp_path):
            findings.extend(_analyze_tmp_entry(child))

    return findings


def collect_tmp_paths(hash_files: bool = False) -> list[dict]:
    artifacts = []

    for tmp_path in TMP_PATHS:
        exists = path_exists(tmp_path)

        artifacts.append(
            {
                "path": str(tmp_path),
                "type": "tmp-location",
                "exists": exists,
                "owner": get_file_owner(tmp_path) if exists else "unknown",
                "permissions": get_file_permissions(tmp_path) if exists else "unknown",
                "sha256": None,
            }
        )

        if not exists or not tmp_path.is_dir():
            continue

        for child in _safe_rglob(tmp_path):
            child_exists = path_exists(child)
            child_is_file = is_file_safe(child)

            artifacts.append(
                {
                    "path": str(child),
                    "type": "tmp-artifact",
                    "exists": child_exists,
                    "owner": get_file_owner(child) if child_exists else "unknown",
                    "permissions": get_file_permissions(child) if child_exists else "unknown",
                    "sha256": sha256_file(child) if hash_files and child_exists and child_is_file else None,
                }
            )

    return artifacts


def _analyze_tmp_entry(path: Path) -> list[dict]:
    findings = []

    score = 0
    reasons = []
    preview_line = None

    name_lower = path.name.lower()

    if path.name.startswith("."):
        score += 15
        reasons.append("Hidden file in temp path")

    for bad_name in SUSPICIOUS_NAMES:
        if bad_name in name_lower:
            score += 10
            reasons.append(f"Suspicious name: {bad_name}")

    perms = get_file_permissions(path)
    if "x" in perms:
        score += 20
        reasons.append("Executable in temp path")

    if is_file_safe(path):
        try:
            content = path.read_text(errors="ignore")
        except:
            content = None

        if content:
            for line in content.splitlines():
                stripped = line.strip()

                if not stripped or stripped.startswith("#"):
                    continue

                for keyword in SUSPICIOUS_KEYWORDS:
                    if keyword in stripped:
                        if preview_line is None:
                            preview_line = stripped
                        score += 20
                        reasons.append(f"Keyword: {keyword}")

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


def _safe_rglob(base: Path):
    try:
        return list(base.rglob("*"))
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