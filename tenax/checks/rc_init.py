from __future__ import annotations

from pathlib import Path

from tenax.utils import is_file_safe, path_exists

RC_PATHS = [
    Path("/etc/init.d"),
    Path("/etc/rc.local"),
]

KEYWORD_RULES = [
    ("curl", 30, "Network retrieval via curl"),
    ("wget", 30, "Network retrieval via wget"),
    ("nc", 35, "Netcat execution detected"),
    ("ncat", 35, "Netcat execution detected"),
    ("bash -c", 30, "Bash command execution"),
    ("sh -c", 30, "Shell command execution"),
    ("python", 20, "Python execution detected"),
    ("perl", 20, "Perl execution detected"),
    ("base64", 25, "Encoded payload usage"),
    ("nohup", 20, "Detached execution (nohup)"),
    ("setsid", 20, "Detached session execution"),
]

PATH_RULES = [
    ("/tmp/", 40, "References /tmp (suspicious execution path)"),
    ("/var/tmp/", 40, "References /var/tmp (suspicious execution path)"),
    ("/dev/shm/", 50, "References in-memory path /dev/shm"),
]

INTERPRETERS = ["#!/bin/sh", "#!/bin/bash"]


def analyze_rc_init_locations() -> list[dict]:
    findings = []

    for base in RC_PATHS:
        if not path_exists(base):
            continue

        if base.is_dir():
            for file in base.iterdir():
                if is_file_safe(file):
                    findings.extend(_analyze_file(file))
        else:
            findings.extend(_analyze_file(base))

    return findings


def _analyze_file(path: Path) -> list[dict]:
    findings = []

    try:
        content = path.read_text(errors="ignore")
    except Exception:
        return findings

    score = 0
    reasons = []
    preview = None

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        lower = stripped.lower()

        # Keyword detection
        for keyword, pts, reason in KEYWORD_RULES:
            if keyword in lower:
                score += pts
                reasons.append(reason)
                if not preview:
                    preview = stripped

        # Path detection
        for keyword, pts, reason in PATH_RULES:
            if keyword in lower:
                score += pts
                reasons.append(reason)
                if not preview:
                    preview = stripped

        # Interpreter detection
        if any(interp in lower for interp in INTERPRETERS):
            score += 10
            reasons.append("Script declares shell interpreter")
            if not preview:
                preview = stripped

    reasons = list(dict.fromkeys(reasons))  # dedupe but preserve order

    if score > 0:
        findings.append(
            {
                "path": str(path),
                "score": score,
                "severity": _severity(score),
                "reason": reasons[0],
                "reasons": reasons,
                "preview": preview,
            }
        )

    return findings


def _severity(score: int) -> str:
    if score >= 100:
        return "HIGH"
    if score >= 60:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"