from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def output_results(
    mode: str,
    results: list[dict[str, Any]],
    output_format: str = "text",
    output_path=None,
    metadata: dict[str, Any] | None = None,
) -> None:
    metadata = metadata or {}

    output_dir = _get_tenax_output_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    extension = "json" if output_format == "json" else "txt"
    auto_output_file = output_dir / f"{mode}_{timestamp}.{extension}"

    if output_path:
        output_path = Path(output_path)
        if output_path.is_dir():
            explicit_output_file = output_path / f"{mode}_{timestamp}.{extension}"
        else:
            explicit_output_file = output_path
    else:
        explicit_output_file = None

    if output_format == "json":
        full_render = json.dumps(
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
        full_render = render_text(mode, results, metadata=metadata)

    auto_output_file.write_text(full_render, encoding="utf-8")

    if explicit_output_file:
        explicit_output_file.parent.mkdir(parents=True, exist_ok=True)
        explicit_output_file.write_text(full_render, encoding="utf-8")

    display_results = results[:5]

    if output_format == "json":
        terminal_render = json.dumps(
            {
                "mode": mode,
                "count": len(display_results),
                "metadata": metadata,
                "results": display_results,
            },
            indent=2,
            default=str,
        )
    else:
        terminal_render = render_text(mode, display_results, metadata=metadata)

    print(terminal_render)

    print("\n" + "=" * 80)
    print(f"[+] Full results saved to: {auto_output_file}")
    if explicit_output_file:
        print(f"[+] Additional output saved to: {explicit_output_file}")
    print("=" * 80)


def render_text(
    mode: str,
    results: list[dict[str, Any]],
    metadata: dict[str, Any] | None = None,
) -> str:
    metadata = metadata or {}

    if mode == "analyze":
        return _render_analyze_text(results, metadata)

    lines: list[str] = []
    lines.append("=== TENAX RESULTS ===")
    lines.append("")
    lines.append(f"Mode: {mode}")
    lines.append(f"Count: {len(results)}")

    if not results:
        lines.append("")
        lines.append("No results found.")
        return "\n".join(lines)

    lines.append("")
    for idx, item in enumerate(results[:5], start=1):
        lines.append("=" * 100)
        lines.append(f"[{idx}] {item.get('path', 'N/A')}")

    return "\n".join(lines).rstrip()


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


def _render_collect_text(results: list[dict[str, Any]]) -> str:
    lines: list[str] = []

    lines.append("=== TENAX COLLECT RESULTS ===")
    lines.append("")

    if not results:
        lines.append("No collection results.")
        return "\n".join(lines)

    lines.append(f"Artifacts collected: {len(results)}")
    lines.append("")

    for idx, result in enumerate(results, start=1):
        lines.append("=" * 100)
        lines.append(
            f"[{idx}] {result.get('module', 'unknown').upper()} | {result.get('artifact_type', 'artifact')}"
        )
        lines.append(f"Path: {result.get('path', 'unknown')}")
        lines.append(f"Discovery: {result.get('discovery_mode', 'unknown')}")

        if result.get("discovered_from"):
            lines.append(f"Discovered From: {result['discovered_from']}")

        if result.get("reference_reason"):
            lines.append(f"Reference Reason: {result['reference_reason']}")

        if result.get("owner"):
            lines.append(f"Owner: {result['owner']}")

        if result.get("group"):
            lines.append(f"Group: {result['group']}")

        if result.get("mode"):
            lines.append(f"Mode: {result['mode']}")

        if result.get("size") is not None:
            lines.append(f"Size: {result['size']}")

        if result.get("sha256"):
            lines.append(f"SHA256: {result['sha256']}")

        if result.get("preview"):
            lines.append(f"Preview: {result['preview']}")

        copy_status = result.get("copy_status") or {}
        if copy_status.get("copied") and copy_status.get("copied_to"):
            lines.append(f"Copied To: {copy_status['copied_to']}")

        references = result.get("references") or []
        if references:
            lines.append("References:")
            for ref in references:
                lines.append(
                    f"  - [{ref.get('ref_type', 'unknown')}] {ref.get('value', 'unknown')} "
                    f"(reason: {ref.get('reason', 'unknown')})"
                )

        lines.append("")

    return "\n".join(lines).rstrip()


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


def _group_findings_by_severity(results):
    grouped = defaultdict(list)
    for r in results:
        grouped[str(r.get("severity", "INFO")).upper()].append(r)
    return grouped


def _ensure_list(value):
    if not value:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _get_tenax_output_dir() -> Path:
    reporter_file = Path(__file__).resolve()
    repo_root = reporter_file.parent.parent
    output_dir = repo_root / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir