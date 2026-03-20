from pathlib import Path

from tenax.utils import (
    get_file_owner,
    get_file_permissions,
    is_file_safe,
    path_exists,
    sha256_file,
)


RC_INIT_PATHS = [
    Path("/etc/rc.local"),
    Path("/etc/init.d"),
    Path("/etc/rc0.d"),
    Path("/etc/rc1.d"),
    Path("/etc/rc2.d"),
    Path("/etc/rc3.d"),
    Path("/etc/rc4.d"),
    Path("/etc/rc5.d"),
    Path("/etc/rc6.d"),
    Path("/etc/rcS.d"),
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
    "nohup",
    "setsid",
    "socat",
    "mkfifo",
]

SUSPICIOUS_NAMES = [
    "update",
    "backup",
    "dbus",
    "network",
    "system",
    "sysinit",
    "kworker",
]


def analyze_rc_init_locations() -> list[dict]:
    findings = []

    for target_path in RC_INIT_PATHS:
        if not path_exists(target_path):
            continue

        if is_file_safe(target_path):
            findings.extend(_analyze_file(target_path))
        elif target_path.is_dir():
            for child in _safe_iterdir(target_path):
                if child.is_file() or child.is_symlink():
                    findings.extend(_analyze_file_or_link(child))

    return findings


def collect_rc_init_locations(hash_files: bool = False) -> list[dict]:
    artifacts = []

    for target_path in RC_INIT_PATHS:
        exists = path_exists(target_path)
        is_file = is_file_safe(target_path)

        artifacts.append(
            {
                "path": str(target_path),
                "type": "rc-init-location",
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
                        "type": "rc-init-artifact",
                        "exists": child_exists,
                        "owner": get_file_owner(child) if child_exists else "unknown",
                        "permissions": get_file_permissions(child) if child_exists else "unknown",
                        "sha256": sha256_file(child) if hash_files and child_exists and child_is_file else None,
                    }
                )

    return artifacts


def _analyze_file_or_link(path: Path) -> list[dict]:
    findings = []

    if path.is_symlink():
        score = 0
        reasons = []

        try:
            target = str(path.resolve())
        except OSError:
            target = ""

        for keyword in ("/tmp/", "/var/tmp/", "/dev/shm/"):
            if keyword in target:
                score += 40
                reasons.append(f"Symlink points to suspicious path: {target}")

        name_lower = path.name.lower()
        for bad_name in SUSPICIOUS_NAMES:
            if bad_name in name_lower:
                score += 10
                reasons.append(f"Suspicious rc symlink name pattern: {bad_name}")

        if score > 0:
            findings.append(
                {
                    "path": str(path),
                    "score": score,
                    "severity": _severity_from_score(score),
                    "reason": "; ".join(_dedupe(reasons)),
                }
            )

        if is_file_safe(path.resolve()) if path_exists(path) else False:
            findings.extend(_analyze_file(path.resolve()))

        return findings

    return _analyze_file(path)


def _analyze_file(path: Path) -> list[dict]:
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
            }
        )
        return findings
    except OSError:
        return findings

    score = 0
    reasons = []

    name_lower = path.name.lower()

    for bad_name in SUSPICIOUS_NAMES:
        if bad_name in name_lower:
            score += 10
            reasons.append(f"Suspicious init script name pattern: {bad_name}")

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in content:
            score += 20
            reasons.append(f"Contains suspicious keyword: {keyword}")

    if path.name.startswith("."):
        score += 15
        reasons.append("Hidden rc/init file name")

    if _contains_network_execution_chain(content):
        score += 40
        reasons.append("Contains likely download-and-execute chain")

    perms = get_file_permissions(path)
    if "w" in perms[5:] or "w" in perms[8:]:
        score += 15
        reasons.append("Group/Other write permissions on rc/init file")

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


def _contains_network_execution_chain(content: str) -> bool:
    lowered = content.lower()
    network_terms = ["curl", "wget"]
    exec_terms = ["bash", "sh", "source", "python", "perl"]

    return any(n in lowered for n in network_terms) and any(e in lowered for e in exec_terms)


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