from __future__ import annotations

from pathlib import Path

from tenax.utils import is_file_safe, path_exists

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

SUSPICIOUS_RULES = [
    {
        "name": "curl-download",
        "pattern": "curl",
        "score": 30,
        "reason": "Init artifact contains network retrieval via curl",
    },
    {
        "name": "wget-download",
        "pattern": "wget",
        "score": 30,
        "reason": "Init artifact contains network retrieval via wget",
    },
    {
        "name": "netcat-execution",
        "pattern": "nc ",
        "score": 35,
        "reason": "Init artifact contains netcat execution logic",
    },
    {
        "name": "python-execution",
        "pattern": "python",
        "score": 20,
        "reason": "Init artifact contains Python execution logic",
    },
    {
        "name": "perl-execution",
        "pattern": "perl",
        "score": 20,
        "reason": "Init artifact contains Perl execution logic",
    },
    {
        "name": "bash-command",
        "pattern": "bash -c",
        "score": 30,
        "reason": "Init artifact contains bash command execution",
    },
    {
        "name": "sh-command",
        "pattern": "sh -c",
        "score": 30,
        "reason": "Init artifact contains shell command execution",
    },
    {
        "name": "temp-path",
        "pattern": "/tmp/",
        "score": 40,
        "reason": "Init artifact references a temporary directory path",
    },
    {
        "name": "shm-path",
        "pattern": "/dev/shm/",
        "score": 45,
        "reason": "Init artifact references an in-memory temporary path",
    },
    {
        "name": "var-tmp-path",
        "pattern": "/var/tmp/",
        "score": 40,
        "reason": "Init artifact references /var/tmp",
    },
    {
        "name": "base64",
        "pattern": "base64",
        "score": 25,
        "reason": "Init artifact contains base64-related content",
    },
    {
        "name": "nohup",
        "pattern": "nohup",
        "score": 20,
        "reason": "Init artifact contains detached execution behavior",
    },
    {
        "name": "setsid",
        "pattern": "setsid",
        "score": 20,
        "reason": "Init artifact contains detached session execution",
    },
]

SHELL_INTERPRETERS = [
    "/bin/sh",
    "/bin/bash",
    "/usr/bin/bash",
    "/usr/bin/sh",
]


def analyze_rc_init_locations() -> list[dict]:
    findings: list[dict] = []

    for path in RC_PATHS:
        if not path_exists(path):
            continue

        if path.is_dir():
            for child in _safe_iterdir(path):
                if not is_file_safe(child):
                    continue
                findings.extend(_analyze_file(child))
            continue

        if is_file_safe(path):
            findings.extend(_analyze_file(path))

    return findings


def collect_rc_init_locations(hash_files: bool = False) -> list[dict]:
    return []


def _analyze_file(path: Path) -> list[dict]:
    findings: list[dict] = []

    try:
        if path.is_symlink():
            findings.extend(_analyze_symlink(path))
            return findings

        content = path.read_text(errors="ignore")
    except Exception:
        return findings

    score = 0
    reasons: list[str] = []
    preview_line: str | None = None
    lowered_lines = content.splitlines()

    for raw_line in lowered_lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        line_lower = stripped.lower()

        for rule in SUSPICIOUS_RULES:
            if rule["pattern"] in line_lower:
                score += int(rule["score"])
                reasons.append(str(rule["reason"]))
                if preview_line is None:
                    preview_line = stripped

        if stripped.startswith("#!") and any(interpreter in line_lower for interpreter in SHELL_INTERPRETERS):
            score += 10
            reasons.append("Init artifact declares a shell interpreter")
            if preview_line is None:
                preview_line = stripped

    unique_reasons = _dedupe_keep_order(reasons)

    if score > 0:
        findings.append(
            {
                "path": str(path),
                "score": score,
                "severity": _severity(score),
                "reason": unique_reasons[0],
                "reasons": unique_reasons,
                "preview": preview_line,
            }
        )

    return findings


def _analyze_symlink(path: Path) -> list[dict]:
    findings: list[dict] = []

    try:
        target = path.resolve(strict=False)
    except Exception:
        return findings

    reasons: list[str] = []
    score = 0

    target_str = str(target)

    if "/tmp/" in target_str:
        score += 50
        reasons.append("Init symlink target points into /tmp")
    if "/var/tmp/" in target_str:
        score += 45
        reasons.append("Init symlink target points into /var/tmp")
    if "/dev/shm/" in target_str:
        score += 55
        reasons.append("Init symlink target points into /dev/shm")

    if score > 0:
        findings.append(
            {
                "path": str(path),
                "score": score,
                "severity": _severity(score),
                "reason": reasons[0],
                "reasons": reasons,
                "preview": f"symlink -> {target}",
            }
        )

    return findings


def _safe_iterdir(path: Path) -> list[Path]:
    try:
        return list(path.iterdir())
    except Exception:
        return []


def _dedupe_keep_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []

    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)

    return output


def _severity(score: int) -> str:
    if score >= 90:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"