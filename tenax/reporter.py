from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


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

    # 🔥 ALWAYS SAVE FULL RESULTS
    output_dir = Path("tenax/output")
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = output_dir / f"{mode}_{timestamp}.txt"

    full_render = render_text(mode, results, metadata=metadata)
    output_file.write_text(full_render, encoding="utf-8")

    # 🔥 TERMINAL = TOP 5 ONLY
    display_results = results[:5]

    terminal_render = render_text(
        mode,
        display_results,
        metadata=metadata,
    )

    print(terminal_render)

    print("\n" + "=" * 80)
    print(f"[+] Full results saved to: {output_file}")
    print("=" * 80)


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
    lines: list[str] = [
        "=== TENAX ANALYZE RESULTS ===",
        "(Top results displayed — full output saved to tenax/output/)",
        "",
    ]

    summary = metadata.get("summary", {})
    filters = metadata.get("filters", {})
    quiet = metadata.get("quiet", False)

    total_results = summary.get("consolidated_finding_count", len(results))
    shown_results = len(results)

    if summary and not quiet:
        lines.extend(_render_summary_block(summary))
        lines.append("")

        lines.append(f"Showing top {shown_results} of {total_results} results")
        lines.append("Full results available in tenax/output/")
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
# FINDING RENDER
# ============================================================

def _render_analyze_finding(index: int, item: dict[str, Any]) -> list[str]:
    lines: list[str] = []

    source = str(item.get("source", "unknown")).replace("_", " ").upper()

    lines.append("=" * 100)
    lines.append(
        f"[{index}] {item.get('finding_id', 'TX-UNSET')} | {source} | {item.get('severity', 'INFO')}"
    )
    lines.append(f"Path: {item.get('path', 'N/A')}")
    lines.append(f"Score: {item.get('score', 0)}")

    reasons = _ensure_list(item.get("reasons"))
    primary_reason = item.get("reason", "No reason provided")

    if len(reasons) <= 1:
        lines.append(f"Reason: {primary_reason}")
    else:
        lines.append(f"Primary Reason: {primary_reason}")
        lines.append("Reasons:")
        for r in reasons:
            lines.append(f"  - {r}")

    sources = _ensure_list(item.get("sources"))
    if sources:
        lines.append(f"Sources: {', '.join(sources)}")

    tags = _ensure_list(item.get("tags"))
    if tags:
        lines.append(f"Tags: {', '.join(tags)}")

    if item.get("dedupe_count", 1) > 1:
        lines.append(f"Merged hits: {item.get('dedupe_count')}")

    score_breakdown = item.get("score_breakdown")
    if score_breakdown:
        lines.append(
            f"Score breakdown: max={score_breakdown.get('max_score')}, "
            f"reasons={score_breakdown.get('reason_count')}, "
            f"sources={score_breakdown.get('source_count')}"
        )

    if item.get("preview"):
        lines.append(f"Preview: {item['preview']}")

    return lines


# ============================================================
# SUMMARY
# ============================================================

def _render_summary_block(summary: dict[str, Any]) -> list[str]:
    lines = ["--- Summary ---"]

    fields = [
        ("module_success_count", "Modules succeeded"),
        ("module_count", "Modules total"),
        ("module_error_count", "Modules failed"),
        ("raw_finding_count", "Raw findings"),
        ("consolidated_finding_count", "Consolidated findings"),
        ("deduplicated_count", "Duplicates collapsed"),
        ("unique_path_count", "Unique paths"),
        ("analysis_duration_ms", "Analysis duration (ms)"),
    ]

    for key, label in fields:
        if key in summary:
            lines.append(f"{label}: {summary[key]}")

    severity_counts = summary.get("severity_counts")
    if severity_counts:
        lines.append(
            "Severity counts: "
            + ", ".join(f"{k}={v}" for k, v in severity_counts.items())
        )

    source_counts = summary.get("source_counts")
    if source_counts:
        lines.append(
            "Top sources: "
            + ", ".join(f"{k}={v}" for k, v in list(source_counts.items())[:5])
        )

    return lines


# ============================================================
# GROUPING
# ============================================================

def _group_findings_by_severity(results):
    grouped = defaultdict(list)
    for r in results:
        grouped[str(r.get("severity", "INFO")).upper()].append(r)
    return grouped


# ============================================================
# HELPERS
# ============================================================

def _ensure_list(value):
    if not value:
        return []
    if isinstance(value, list):
        return value
    return [value]