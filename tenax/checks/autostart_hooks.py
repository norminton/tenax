from pathlib import Path

from tenax.utils import get_file_owner, get_file_permissions, is_file_safe, path_exists, sha256_file


SYSTEM_PATHS = [
    Path("/etc/xdg/autostart"),
]

USER_PATHS = [
    ".config/autostart",
]


SUSPICIOUS_KEYWORDS = [
    "curl",
    "wget",
    "bash",
    "sh",
    "/tmp/",
    "/dev/shm/",
]


def analyze_autostart_hook_locations():
    findings = []

    for path in SYSTEM_PATHS:
        if not path_exists(path):
            continue

        for child in _safe_rglob(path):
            if is_file_safe(child):
                findings.extend(_analyze_file(child))

    for home in _get_home_dirs():
        for rel in USER_PATHS:
            target = home / rel
            if not path_exists(target):
                continue

            for child in _safe_rglob(target):
                if is_file_safe(child):
                    findings.extend(_analyze_file(child))

    return findings


def collect_autostart_hook_locations(hash_files=False):
    return []


def _analyze_file(path: Path):
    findings = []

    try:
        content = path.read_text(errors="ignore")
    except:
        return findings

    score = 0
    reasons = []
    preview_line = None

    exec_line = _extract_exec(content)

    if exec_line:
        preview_line = f"Exec={exec_line}"

        if exec_line.startswith("/tmp"):
            score += 40
            reasons.append("Exec from /tmp")

    for line in content.splitlines():
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in stripped:
                if preview_line is None:
                    preview_line = stripped
                score += 20
                reasons.append(keyword)

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


def _extract_exec(content):
    for line in content.splitlines():
        if line.strip().startswith("Exec="):
            return line.split("=", 1)[1].strip()
    return None


def _get_home_dirs():
    homes = []
    base = Path("/home")

    if base.exists():
        for user in base.iterdir():
            if user.is_dir():
                homes.append(user)

    homes.append(Path("/root"))
    return homes


def _safe_rglob(path):
    try:
        return list(path.rglob("*"))
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