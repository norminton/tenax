from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

PREVIEW_KEYWORDS = [
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
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "LD_PRELOAD",
    "Exec=",
    "ExecStart=",
    "NOPASSWD",
    "ALL=(ALL)",
    "ALL=(ALL:ALL)",
    "command=",
    "Hidden=true",
]

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ============================================================
# ENTRY POINT
# ============================================================

def output_results(
    mode: str,
    results: list[dict[str, Any]],
    output_format: str = "text",
    output_path=None,
    metadata: dict[str, Any] | None = None,
) -> None:
    metadata = metadata or {}

    if output_format == "json":
        rendered = json.dumps(
            {
                "mode": mode,
                "count": len(results),
                "metadata": metadata,
                "results": results,
            },
            indent=2,
            default=str,
        )
    else:
        rendered = render_text(mode, results, metadata=metadata)

    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
        print(f"[+] Wrote {mode} results to: {path}")
    else:
        print(rendered)


# ============================================================
# MAIN RENDERER
# ============================================================

def render_text(
    mode: str,
    results: list[dict[str, Any]],
    metadata: dict[str, Any] | None = None,
) -> str:
    metadata = metadata or {}

    if mode == "analyze":
        return _render_analyze_text(results, metadata)

    return _render_collect_text(results)


# ============================================================
# ANALYZE MODE
# ============================================================

def _render_analyze_text(
    results: list[dict[str, Any]],
    metadata: dict[str, Any],
) -> str:
    lines: list[str] = ["=== TENAX ANALYZE RESULTS ===", ""]

    summary = metadata.get("summary", {})
    filters = metadata.get("filters", {})
    quiet = metadata.get("quiet", False)

    # Only show summary if NOT quiet
    if summary and not quiet:
        lines.extend(_render_summary_block(summary))
        lines.append("")

    if filters and any(value not in (None, [], False, "", "score", 20) for value in filters.values()):
        lines.extend(_render_filter_block(filters))
        lines.append("")

    if not results:
        lines.append("No results found.")
        return "\n".join(lines)

    grouped = _group_findings_by_severity(results)

    for severity in SEVERITY_ORDER:
        findings = grouped.get(severity, [])
        if not findings:
            continue

        lines.append(f"=== {severity} FINDINGS ({len(findings)}) ===")
        lines.append("")

        for index, item in enumerate(findings, start=1):
            lines.extend(_render_analyze_finding(index, item))
            lines.append("")

    return "\n".join(lines).rstrip()


# ============================================================
# 🔥 FINDING RENDER (THIS IS WHAT YOU CARE ABOUT)
# ============================================================

def _render_analyze_finding(index: int, item: dict[str, Any]) -> list[str]:
    lines: list[str] = []

    source = str(item.get("source", "unknown")).replace("_", " ").upper()
    path_value = item.get("path", "N/A")

    preview = item.get("preview")
    if not preview:
        preview = _get_artifact_preview(str(path_value)) if path_value != "N/A" else None

    lines.append("=" * 100)
    lines.append(
        f"[{index}] {item.get('finding_id', 'TX-UNSET')} | {source} | {item.get('severity', 'INFO')}"
    )
    lines.append(f"Path: {path_value}")
    lines.append(f"Score: {item.get('score', 0)}")

    # 🔥 MULTI-REASON DISPLAY FIX
    reasons = _ensure_list_of_strings(item.get("reasons"))
    primary_reason = item.get("reason", "No reason provided")

    if len(reasons) <= 1:
        lines.append(f"Reason: {primary_reason}")
    else:
        lines.append("Reasons:")
        for reason in reasons:
            lines.append(f"  - {reason}")

    sources = _ensure_list_of_strings(item.get("sources"))
    if sources:
        lines.append(f"Sources: {', '.join(sources)}")

    tags = _ensure_list_of_strings(item.get("tags"))
    if tags:
        lines.append(f"Tags: {', '.join(tags)}")

    dedupe_count = item.get("dedupe_count")
    if dedupe_count and int(dedupe_count) > 1:
        lines.append(f"Merged hits: {dedupe_count}")

    score_breakdown = item.get("score_breakdown", {})
    if score_breakdown:
        lines.append(
            f"Score breakdown: max={score_breakdown.get('max_score', 0)}, "
            f"reasons={score_breakdown.get('reason_count', 0)}, "
            f"sources={score_breakdown.get('source_count', 0)}"
        )

    recommendation = _derive_triage_recommendation(item)
    if recommendation:
        lines.append(f"Triage next step: {recommendation}")

    if preview:
        lines.append(f"Preview: {preview}")

    return lines


# ============================================================
# SUMMARY / GROUPING
# ============================================================

def _render_summary_block(summary: dict[str, Any]) -> list[str]:
    lines = ["--- Summary ---"]

    for key, label in [
        ("module_success_count", "Modules succeeded"),
        ("module_count", "Modules total"),
        ("module_error_count", "Modules failed"),
        ("raw_finding_count", "Raw findings"),
        ("consolidated_finding_count", "Consolidated findings"),
        ("deduplicated_count", "Duplicates collapsed"),
        ("unique_path_count", "Unique paths"),
        ("temp_path_finding_count", "Temp-path findings"),
        ("analysis_duration_ms", "Analysis duration (ms)"),
    ]:
        if key in summary:
            lines.append(f"{label}: {summary[key]}")

    severity_counts = summary.get("severity_counts", {})
    if severity_counts:
        lines.append(
            "Severity counts: "
            + ", ".join(f"{k}={v}" for k, v in severity_counts.items())
        )

    source_counts = summary.get("source_counts", {})
    if source_counts:
        lines.append(
            "Top sources: "
            + ", ".join(f"{k}={v}" for k, v in list(source_counts.items())[:5])
        )

    return lines


def _render_filter_block(filters: dict[str, Any]) -> list[str]:
    lines = ["--- Active Filters ---"]
    for k, v in filters.items():
        if v not in (None, [], False, ""):
            lines.append(f"{k}: {v}")
    return lines


def _group_findings_by_severity(results: list[dict[str, Any]]):
    grouped = defaultdict(list)
    for item in results:
        grouped[str(item.get("severity", "INFO")).upper()].append(item)
    return grouped


# ============================================================
# HELPERS
# ============================================================

def _derive_triage_recommendation(item: dict[str, Any]) -> str:
    tags = set(_ensure_list_of_strings(item.get("tags")))
    source = str(item.get("source", "")).lower()

    if source == "systemd":
        return "Inspect service unit and ExecStart target."
    if source == "cron":
        return "Validate scheduled command and execution context."
    if "ssh-persistence" in tags:
        return "Verify authorized_keys provenance."
    if "temp-path" in tags:
        return "Inspect file contents and execution lineage."

    return "Validate file ownership, permissions, and execution context."


def _get_artifact_preview(path_value: str, max_length: int = 150) -> str | None:
    path = Path(path_value)

    try:
        if not path.exists():
            return None

        raw = path.read_bytes()
        if b"\x00" in raw[:2048]:
            return "[binary content omitted]"

        content = raw.decode(errors="ignore")

        for line in content.splitlines():
            if any(k in line for k in PREVIEW_KEYWORDS):
                return line[:max_length]

        return content.splitlines()[0][:max_length] if content else None

    except Exception:
        return None


def _ensure_list_of_strings(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value if v]