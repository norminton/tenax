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

    name_lower = path.name.lower()

    if path.name.startswith("."):
        score += 15
        reasons.append("Hidden file or directory in temp path")

    for bad_name in SUSPICIOUS_NAMES:
        if bad_name in name_lower:
            score += 10
            reasons.append(f"Suspicious temp artifact name pattern: {bad_name}")

    perms = get_file_permissions(path)
    if "x" in perms:
        score += 20
        reasons.append("Executable permissions set in temp path")

    if path.is_symlink():
        try:
            target = str(path.resolve())
            if target.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
                score += 20
                reasons.append(f"Symlink points within temp path: {target}")
        except OSError:
            pass

    if is_file_safe(path):
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except PermissionError:
            content = None
            score += 5
            reasons.append("File could not be read due to permissions")
        except OSError:
            content = None

        if content:
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in content:
                    score += 20
                    reasons.append(f"Contains suspicious keyword: {keyword}")

            if _contains_network_execution_chain(content):
                score += 40
                reasons.append("Contains likely download-and-execute chain")

            if _contains_reverse_shell_indicators(content):
                score += 40
                reasons.append("Contains likely reverse shell indicators")

            if content.startswith("#!"):
                score += 10
                reasons.append("Script file located in temp path")

    if path.is_dir():
        try:
            if not any(path.iterdir()):
                score += 5
                reasons.append("Empty directory in temp path")
        except (PermissionError, OSError):
            pass

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


def _contains_reverse_shell_indicators(content: str) -> bool:
    lowered = content.lower()
    indicators = [
        "/dev/tcp/",
        "nc -e",
        "bash -i",
        "sh -i",
        "mkfifo",
        "socat",
    ]
    return any(indicator in lowered for indicator in indicators)


def _safe_rglob(base: Path) -> list[Path]:
    results = []

    try:
        for child in base.rglob("*"):
            results.append(child)
    except (PermissionError, OSError):
        pass

    return results


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
