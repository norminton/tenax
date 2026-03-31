from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from tenax.checks.common import (
    build_collect_record_with_metadata,
    owner_from_uid,
    path_startswith_any,
    record_hit,
    safe_stat,
    select_investigator_preview,
    severity_from_score,
)
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

TEMP_PATH_PATTERNS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/shm/",
)

USER_PATH_REGEX = re.compile(
    r"^(/home/[^/\s]+/|/root/\.|/root/\.local/|/root/\.cache/)",
    re.IGNORECASE,
)

HIDDEN_PATH_REGEX = re.compile(
    r"""
    (
        /tmp/|/var/tmp/|/dev/shm/|/run/shm/|
        /home/[^/\s]+/|/root/
    )
    \.[^/\s'"]+
    """,
    re.IGNORECASE | re.VERBOSE,
)

HIGH_RISK_CAPABILITIES = {
    "cap_setuid": 95,
    "cap_setgid": 90,
    "cap_sys_admin": 100,
    "cap_sys_ptrace": 95,
    "cap_dac_override": 90,
    "cap_dac_read_search": 85,
    "cap_sys_module": 100,
    "cap_sys_rawio": 95,
    "cap_sys_chroot": 70,
    "cap_net_admin": 80,
    "cap_net_raw": 75,
    "cap_bpf": 90,
    "cap_checkpoint_restore": 85,
}

MEDIUM_RISK_CAPABILITIES = {
    "cap_chown": 25,
    "cap_fowner": 30,
    "cap_fsetid": 25,
    "cap_kill": 35,
    "cap_mknod": 35,
    "cap_setfcap": 45,
    "cap_setpcap": 45,
    "cap_net_bind_service": 20,
    "cap_audit_write": 20,
}

ELF_MAGIC = b"\x7fELF"
MODULE_LIMITATION_KEY = "_tenax_limitations"


def analyze_capabilities() -> list[dict[str, Any]]:
    setattr(analyze_capabilities, MODULE_LIMITATION_KEY, [])
    findings: list[dict[str, Any]] = []

    if shutil.which("getcap") is None:
        setattr(
            analyze_capabilities,
            MODULE_LIMITATION_KEY,
            [
                {
                    "type": "unsupported_dependency",
                    "code": "missing_getcap",
                    "message": "Capability analysis skipped because the 'getcap' command is unavailable.",
                    "dependency": "getcap",
                }
            ],
        )
        return []

    for scan_path in CAPABILITY_SCAN_PATHS:
        if not path_exists(scan_path):
            continue
        findings.extend(_run_getcap(scan_path))

    return findings


def collect_capabilities(hash_files: bool = False) -> list[dict[str, Any]]:
    setattr(collect_capabilities, MODULE_LIMITATION_KEY, [])
    artifacts: list[dict[str, Any]] = []

    if shutil.which("getcap") is None:
        setattr(
            collect_capabilities,
            MODULE_LIMITATION_KEY,
            [
                {
                    "type": "unsupported_dependency",
                    "code": "missing_getcap",
                    "message": "Capability collection skipped because the 'getcap' command is unavailable.",
                    "dependency": "getcap",
                }
            ],
        )
        return artifacts

    seen_paths: set[str] = set()

    for scan_path in CAPABILITY_SCAN_PATHS:
        if not path_exists(scan_path):
            continue

        for record in _run_getcap_collect(scan_path):
            path_value = record["path"]
            if path_value in seen_paths:
                continue
            seen_paths.add(path_value)

            path_obj = Path(path_value)
            artifacts.append(_build_collect_record(path_obj, record["capabilities"], hash_files))

    return artifacts


def _run_getcap(scan_path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

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

    for raw_line in result.stdout.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue

        parsed = _parse_getcap_line(stripped)
        if not parsed:
            continue

        path_obj, capabilities_text = parsed
        finding = _analyze_capability_record(path_obj, capabilities_text)
        if finding:
            findings.append(finding)

    return findings


def _run_getcap_collect(scan_path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    try:
        result = subprocess.run(
            ["getcap", "-r", str(scan_path)],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return records

    if result.returncode not in (0, 1):
        return records

    for raw_line in result.stdout.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue

        parsed = _parse_getcap_line(stripped)
        if not parsed:
            continue

        path_obj, capabilities_text = parsed
        records.append(
            {
                "path": str(path_obj),
                "capabilities": capabilities_text,
            }
        )

    return records


def _analyze_capability_record(path_obj: Path, capabilities_text: str) -> dict[str, Any] | None:
    hits: dict[str, dict[str, Any]] = {}
    path_value = str(path_obj)
    path_lower = path_value.lower()
    capability_names = _extract_capability_names(capabilities_text)

    if not capability_names:
        return None

    record_hit(
        hits,
        reason="File has Linux capabilities assigned",
        score=10,
        preview=f"{path_value} = {capabilities_text}",
        category="has-capabilities",
    )

    for capability in capability_names:
        if capability in HIGH_RISK_CAPABILITIES:
            record_hit(
                hits,
                reason=f"High-risk Linux capability present: {capability}",
                score=HIGH_RISK_CAPABILITIES[capability],
                preview=f"{path_value} = {capabilities_text}",
                category=f"cap-{capability}",
            )
        elif capability in MEDIUM_RISK_CAPABILITIES:
            record_hit(
                hits,
                reason=f"Elevated Linux capability present: {capability}",
                score=MEDIUM_RISK_CAPABILITIES[capability],
                preview=f"{path_value} = {capabilities_text}",
                category=f"cap-{capability}",
            )

    if path_startswith_any(path_lower, TEMP_PATH_PATTERNS):
        record_hit(
            hits,
            reason="Capabilities assigned to a file in a temporary path",
            score=100,
            preview=f"{path_value} = {capabilities_text}",
            category="temp-path",
        )
    elif USER_PATH_REGEX.search(path_value):
        record_hit(
            hits,
            reason="Capabilities assigned to a file in a user-controlled path",
            score=95,
            preview=f"{path_value} = {capabilities_text}",
            category="user-path",
        )
    elif HIDDEN_PATH_REGEX.search(path_value):
        record_hit(
            hits,
            reason="Capabilities assigned to a file at a hidden path",
            score=85,
            preview=f"{path_value} = {capabilities_text}",
            category="hidden-path",
        )

    if path_lower.startswith("/opt/"):
        record_hit(
            hits,
            reason="Capabilities assigned to a file under /opt",
            score=35,
            preview=f"{path_value} = {capabilities_text}",
            category="opt-path",
        )

    stat_info = safe_stat(path_obj)
    if stat_info:
        mode = stat_info.st_mode & 0o777
        owner_name = owner_from_uid(stat_info.st_uid)

        if stat_info.st_uid != 0:
            record_hit(
                hits,
                reason="Capability-bearing file is owned by a non-root account",
                score=95,
                preview=f"owner={owner_name}",
                category="ownership",
            )

        if mode & 0o002:
            record_hit(
                hits,
                reason="Capability-bearing file is world-writable",
                score=100,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )
        elif mode & 0o020:
            record_hit(
                hits,
                reason="Capability-bearing file is group-writable",
                score=65,
                preview=f"mode={oct(mode)}",
                category="permissions",
            )

        if path_obj.is_file():
            try:
                raw = path_obj.read_bytes()[:4]
                if raw != ELF_MAGIC:
                    record_hit(
                        hits,
                        reason="Capabilities assigned to a non-ELF file",
                        score=70,
                        preview=f"{path_value} = {capabilities_text}",
                        category="non-elf",
                    )
            except OSError:
                pass

    _apply_compound_behavior_bonuses(hits)

    return _finalize_finding(path_obj, capabilities_text, hits)

def _apply_compound_behavior_bonuses(hits: dict[str, dict[str, Any]]) -> None:
    categories = {entry["category"] for entry in hits.values()}

    if any(category.startswith("cap-cap_setuid") or category.startswith("cap-cap_setgid") for category in categories):
        if "user-path" in categories or "temp-path" in categories or "ownership" in categories:
            record_hit(
                hits,
                reason="Privilege-related capabilities are assigned to a high-risk file location",
                score=35,
                preview=None,
                category="compound-priv-path",
            )

    if any(category.startswith("cap-cap_sys_admin") or category.startswith("cap-cap_sys_ptrace") for category in categories):
        record_hit(
            hits,
            reason="Capabilities include highly sensitive system-level privilege",
            score=25,
            preview=None,
            category="compound-high-priv",
        )

    if "permissions" in categories and ("user-path" in categories or "temp-path" in categories):
        record_hit(
            hits,
            reason="Writable file with capabilities exists in a high-risk path",
            score=40,
            preview=None,
            category="compound-writable-risk-path",
        )


def _finalize_finding(
    path_obj: Path,
    capabilities_text: str,
    hits: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    if not hits:
        return None

    reasons = [entry["reason"] for entry in hits.values()]
    categories = {entry["category"] for entry in hits.values()}
    score = sum(int(entry["score"]) for entry in hits.values())

    high_confidence_categories = {
        "temp-path",
        "user-path",
        "hidden-path",
        "ownership",
        "permissions",
        "non-elf",
        "compound-priv-path",
        "compound-high-priv",
        "compound-writable-risk-path",
    }

    has_high_confidence = bool(categories & high_confidence_categories)

    if not has_high_confidence and score < 80:
        return None

    primary_reason = max(
        hits.values(),
        key=lambda entry: int(entry["score"]),
    )["reason"]

    preview = select_investigator_preview(hits, fallback=f"{path_obj} = {capabilities_text}")

    return {
        "path": str(path_obj),
        "score": score,
        "severity": severity_from_score(score),
        "reason": primary_reason,
        "reasons": reasons,
        "preview": preview,
    }


def _parse_getcap_line(line: str) -> tuple[Path, str] | None:
    if " = " not in line:
        return None

    path_part, capabilities_part = line.split(" = ", 1)
    path_part = path_part.strip()
    capabilities_part = capabilities_part.strip()

    if not path_part or not capabilities_part:
        return None

    return Path(path_part), capabilities_part


def _extract_capability_names(capabilities_text: str) -> list[str]:
    capability_names: list[str] = []

    left_side = capabilities_text.split("+", 1)[0]
    for chunk in left_side.split(","):
        name = chunk.strip().lower()
        if name:
            capability_names.append(name)

    return capability_names


def _build_collect_record(path: Path, capabilities_text: str, hash_files: bool = False) -> dict[str, Any]:
    return build_collect_record_with_metadata(
        path,
        hash_files=hash_files,
        extra_fields={"capabilities": capabilities_text},
    )
