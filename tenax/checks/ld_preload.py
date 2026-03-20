from pathlib import Path

from tenax.utils import (
    get_file_owner,
    get_file_permissions,
    is_file_safe,
    path_exists,
    sha256_file,
)


LD_PRELOAD_PATHS = [
    Path("/etc/ld.so.preload"),
    Path("/etc/ld.so.conf"),
    Path("/etc/ld.so.conf.d"),
]

SUSPICIOUS_LIBRARY_PATHS = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/home/",
]

SUSPICIOUS_KEYWORDS = [
    "LD_PRELOAD",
    ".so",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
]


def analyze_ld_preload_locations() -> list[dict]:
    findings = []

    for target_path in LD_PRELOAD_PATHS:
        if not path_exists(target_path):
            continue

        if is_file_safe(target_path):
            findings.extend(_analyze_ld_file(target_path))
        elif target_path.is_dir():
            for child in _safe_iterdir(target_path):
                if is_file_safe(child):
                    findings.extend(_analyze_ld_file(child))

    return findings


def collect_ld_preload_locations(hash_files: bool = False) -> list[dict]:
    artifacts = []

    for target_path in LD_PRELOAD_PATHS:
        exists = path_exists(target_path)
        is_file = is_file_safe(target_path)

        artifacts.append(
            {
                "path": str(target_path),
                "type": "ld-preload-location",
                "exists": exists,
                "owner": get_file_owner(target_path) if exists else "unknown",
                "permissions": get_file_permissions(target_path) if exists else "unknown",
                "sha256": sha256_file(target_path) if hash_files and exists and is_file else None,
            }
        )

        if exists and target_path.is_dir():
            for child in _safe_iterdir(target_path):
                child_exists = path_exists(child)
                child_is_file = is_file_safe(child)

                artifacts.append(
                    {
                        "path": str(child),
                        "type": "ld-preload-artifact",
                        "exists": child_exists,
                        "owner": get_file_owner(child) if child_exists else "unknown",
                        "permissions": get_file_permissions(child) if child_exists else "unknown",
                        "sha256": sha256_file(child) if hash_files and child_exists and child_is_file else None,
                    }
                )

    return artifacts


def _analyze_ld_file(path: Path) -> list[dict]:
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

    for line in content.splitlines():
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in stripped:
                if preview_line is None:
                    preview_line = stripped
                score += 10
                reasons.append(f"Contains loader-related keyword: {keyword}")

        if ".so" in stripped:
            if preview_line is None:
                preview_line = stripped
            score += 20
            reasons.append("References shared object library")

        for bad_path in SUSPICIOUS_LIBRARY_PATHS:
            if bad_path in stripped:
                if preview_line is None:
                    preview_line = stripped
                score += 40
                reasons.append(f"References library in suspicious path: {bad_path}")

        if stripped.startswith("include "):
            if preview_line is None:
                preview_line = stripped
            score += 5
            reasons.append("Uses include directive in loader config")

    perms = get_file_permissions(path)
    if "w" in perms[5:] or "w" in perms[8:]:
        score += 15
        reasons.append("Group/Other write permissions on loader file")

    if path.name.startswith("."):
        score += 10
        reasons.append("Hidden loader-related file name")

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