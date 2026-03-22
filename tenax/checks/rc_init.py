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

KEYWORD_RULES = [
    ("curl", 30, "Init artifact contains network retrieval via curl"),
    ("wget", 30, "Init artifact contains network retrieval via wget"),
    ("nc", 35, "Init artifact contains netcat execution logic"),
    ("ncat", 35, "Init artifact contains netcat execution logic"),
    ("bash -c", 30, "Init artifact contains bash command execution"),
    ("sh -c", 30, "Init artifact contains shell command execution"),
    ("python", 20, "Init artifact contains Python execution logic"),
    ("perl", 20, "Init artifact contains Perl execution logic"),
    ("base64", 25, "Init artifact contains base64-related content"),
    ("nohup", 20, "Init artifact contains detached execution behavior"),
    ("setsid", 20, "Init artifact contains detached session execution"),
]

PATH_RULES = [
    ("/tmp/", 40, "Init artifact references /tmp"),
    ("/var/tmp/", 40, "Init artifact references /var/tmp"),
    ("/dev/shm/", 50, "Init artifact references /dev/shm"),
]

INTERPRETERS = [
    "#!/bin/sh",
    "#!/bin/bash",
    "#!/usr/bin/sh",
    "#!/usr/bin/bash",
]


def analyze_rc_init_locations() -> list[dict]:
    findings: list[dict] = []

    for base in RC_PATHS:
        if not path_exists(base):
            continue

        if base.is_dir():
            for child in _safe_iterdir(base):
                if not is_file_safe(child):
                    continue
                findings.extend(_analyze_file(child))
        else:
            if is_file_safe(base):
                findings.extend(_analyze_file(base))

    return findings


def collect_rc_init_locations(hash_files: bool = False) -> list[dict]:
    artifacts: list[dict] = []

    for base in RC_PATHS:
        if not path_exists(base):
            continue

        if base.is_dir():
            for child in _safe_iterdir(base):
                if not is_file_safe(child):
                    continue
                artifacts.append(_build_collect_record(child, hash_files=hash_files))
        else:
            if is_file_safe(base):
                artifacts.append(_build_collect_record(base, hash_files=hash_files))

    return artifacts


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
    preview: str | None = None

    for raw_line in content.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue

        lower = stripped.lower()

        if stripped.startswith("#!") and any(interpreter in lower for interpreter in INTERPRETERS):
            score += 10
            reasons.append("Init artifact declares a shell interpreter")
            if preview is None:
                preview = stripped

        if stripped.startswith("#"):
            continue

        for keyword, points, reason in KEYWORD_RULES:
            if keyword in lower:
                score += points
                reasons.append(reason)
                if preview is None:
                    preview = stripped

        for keyword, points, reason in PATH_RULES:
            if keyword in lower:
                score += points
                reasons.append(reason)
                if preview is None:
                    preview = stripped

    unique_reasons = _dedupe_keep_order(reasons)

    if score > 0:
        findings.append(
            {
                "path": str(path),
                "score": score,
                "severity": _severity(score),
                "reason": unique_reasons[0],
                "reasons": unique_reasons,
                "preview": preview,
            }
        )

    return findings


def _analyze_symlink(path: Path) -> list[dict]:
    findings: list[dict] = []

    try:
        target = path.resolve(strict=False)
    except Exception:
        return findings

    target_str = str(target)
    score = 0
    reasons: list[str] = []

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


def _build_collect_record(path: Path, hash_files: bool = False) -> dict:
    record = {
        "path": str(path),
        "type": "artifact",
        "exists": path.exists(),
        "owner": "unknown",
        "permissions": "unknown",
    }

    try:
        stat_info = path.lstat() if path.is_symlink() else path.stat()
        record["permissions"] = oct(stat_info.st_mode & 0o777)
    except Exception:
        pass

    try:
        import pwd

        stat_info = path.lstat() if path.is_symlink() else path.stat()
        record["owner"] = pwd.getpwuid(stat_info.st_uid).pw_name
    except Exception:
        pass

    if hash_files and path.exists() and path.is_file() and not path.is_symlink():
        try:
            import hashlib

            sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
            record["sha256"] = sha256
        except Exception:
            pass

    return record


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
    if score >= 100:
        return "HIGH"
    if score >= 60:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"