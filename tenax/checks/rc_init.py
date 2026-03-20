from pathlib import Path

from tenax.utils import get_file_owner, get_file_permissions, is_file_safe, path_exists, sha256_file


RC_PATHS = [
    Path("/etc/rc.local"),
    Path("/etc/init.d"),
    Path("/etc/rc0.d"),
    Path("/etc/rc1.d"),
    Path("/etc/rc2.d"),
    Path("/etc/rc3.d"),
    Path("/etc/rc4.d"),
    Path("/etc/rc5.d"),
    Path("/etc/rc6.d"),
]


SUSPICIOUS_KEYWORDS = [
    "curl",
    "wget",
    "bash",
    "sh",
    "nc ",
    "python",
    "perl",
    "/tmp/",
    "/dev/shm/",
]


def analyze_rc_init_locations():
    findings = []

    for path in RC_PATHS:
        if not path_exists(path):
            continue

        if is_file_safe(path):
            findings.extend(_analyze_file(path))

        elif path.is_dir():
            for child in _safe_iterdir(path):
                if is_file_safe(child):
                    findings.extend(_analyze_file(child))

    return findings


def collect_rc_init_locations(hash_files=False):
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


def _safe_iterdir(path):
    try:
        return list(path.iterdir())
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