import shutil
import subprocess
from pathlib import Path

from tenax.utils import path_exists


CAPABILITY_SCAN_PATHS = [
    Path("/bin"),
    Path("/sbin"),
    Path("/usr/bin"),
    Path("/usr/sbin"),
    Path("/usr/local/bin"),
    Path("/usr/local/sbin"),
    Path("/opt"),
    Path("/home"),
    Path("/tmp"),
    Path("/var/tmp"),
]

HIGH_RISK_CAPABILITIES = [
    "cap_setuid",
    "cap_setgid",
    "cap_sys_admin",
    "cap_sys_ptrace",
    "cap_dac_override",
    "cap_dac_read_search",
]

SUSPICIOUS_PATHS = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/home/",
    "/opt/",
]


def analyze_capabilities() -> list[dict]:
    findings = []

    if shutil.which("getcap") is None:
        return [
            {
                "path": "getcap",
                "score": 0,
                "severity": "INFO",
                "reason": "getcap command not available; capability scan skipped",
                "preview": "Install libcap tools to enable capability scanning",
            }
        ]

    for scan_path in CAPABILITY_SCAN_PATHS:
        if not path_exists(scan_path):
            continue

        findings.extend(_run_getcap(scan_path))

    return findings


def collect_capabilities(hash_files: bool = False) -> list[dict]:
    # Capabilities are effectively collected through analysis output for now.
    # This keeps the collector stable without requiring binary parsing.
    return []


def _run_getcap(scan_path: Path) -> list[dict]:
    findings = []

    try:
        result = subprocess.run(
            ["getcap", "-r", str(scan_path)],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return findings

    if result.returncode not in (0, 1):
        return findings

    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        score = 0
        reasons = []
        preview_line = stripped

        path_part, _, caps_part = stripped.partition(" = ")
        if not caps_part:
            continue

        for cap in HIGH_RISK_CAPABILITIES:
            if cap in caps_part:
                score += 35
                reasons.append(f"High-risk Linux capability present: {cap}")

        for bad_path in SUSPICIOUS_PATHS:
            if bad_path in path_part:
                score += 25
                reasons.append(f"Capability assigned in suspicious path: {bad_path}")

        if caps_part:
            score += 10
            reasons.append("File has Linux capabilities assigned")

        if score > 0:
            findings.append(
                {
                    "path": path_part,
                    "score": score,
                    "severity": _severity_from_score(score),
                    "reason": "; ".join(_dedupe(reasons)),
                    "preview": preview_line,
                }
            )

    return findings


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