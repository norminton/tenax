from __future__ import annotations

import json
import re
import textwrap
from collections import defaultdict
from typing import Any

from tenax.output_paths import resolve_output_file
from tenax.output_paths import resolve_runtime_output_dir

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
HEADER_RULE = "═" * 54
SECTION_RULE = "-" * 54
LINE_PREVIEW_REGEX = re.compile(r"^(?:line\s+|L)(\d+):\s*(.+)$", re.IGNORECASE)


def output_results(
    mode: str,
    results: list[dict[str, Any]],
    output_format: str = "text",
    output_path=None,
    metadata: dict[str, Any] | None = None,
    *,
    display_results: list[dict[str, Any]] | None = None,
) -> None:
    metadata = metadata or {}
    saved_results = results
    terminal_results = display_results if display_results is not None else results

    extension = "json" if output_format == "json" else "txt"
    if output_path:
        auto_output_file, explicit_output_file = resolve_output_file(
            mode=mode,
            extension=extension,
            explicit_path=output_path,
        )
    else:
        timestamped_file, explicit_output_file = resolve_output_file(
            mode=mode,
            extension=extension,
            explicit_path=None,
        )
        auto_output_file = _get_tenax_output_dir() / timestamped_file.name

    full_render = _render(mode, saved_results, output_format, metadata)
    auto_output_file.parent.mkdir(parents=True, exist_ok=True)
    auto_output_file.write_text(full_render, encoding="utf-8")

    if explicit_output_file:
        explicit_output_file.parent.mkdir(parents=True, exist_ok=True)
        explicit_output_file.write_text(full_render, encoding="utf-8")

    terminal_metadata = dict(metadata)
    summary = dict(terminal_metadata.get("summary", {}))
    if "displayed_finding_count" in summary:
        summary["displayed_finding_count"] = len(terminal_results)
    if "saved_finding_count" in summary:
        summary["saved_finding_count"] = len(saved_results)
    terminal_metadata["summary"] = summary
    terminal_metadata["output_locations"] = {
        "saved": str(auto_output_file),
        "explicit": str(explicit_output_file) if explicit_output_file else None,
    }

    terminal_render = _render(mode, terminal_results, output_format, terminal_metadata)
    print(terminal_render)
    if output_format == "json":
        print(f"Saved full {mode} output to: {auto_output_file}")
        if explicit_output_file:
            print(f"Saved additional {mode} output to: {explicit_output_file}")


def _render(
    mode: str,
    results: list[dict[str, Any]],
    output_format: str,
    metadata: dict[str, Any],
) -> str:
    if output_format == "json":
        return json.dumps(
            {
                "mode": mode,
                "count": len(results),
                "metadata": metadata,
                "results": results,
            },
            indent=2,
            default=str,
        )
    return render_text(mode, results, metadata=metadata)


def render_text(
    mode: str,
    results: list[dict[str, Any]],
    metadata: dict[str, Any] | None = None,
) -> str:
    metadata = metadata or {}
    if mode == "analyze":
        return _render_analyze_text(results, metadata)
    if mode == "collect":
        return _render_collect_text(results, metadata)

    lines = ["=== TENAX RESULTS ===", f"Mode: {mode}", f"Count: {len(results)}"]
    if not results:
        lines.append("No results found.")
        return "\n".join(lines)
    return "\n".join(lines)


def _render_analyze_text(results: list[dict[str, Any]], metadata: dict[str, Any]) -> str:
    lines: list[str] = [
        HEADER_RULE,
        "              TENAX PERSISTENCE ANALYSIS",
        HEADER_RULE,
    ]
    summary = metadata.get("summary", {})
    quiet = bool(metadata.get("quiet", False))

    if summary and not quiet:
        total = summary.get("filtered_finding_count", len(results))
        shown = summary.get("displayed_finding_count", len(results))
        saved = summary.get("saved_finding_count", total)
        lines.extend(_render_severity_summary(summary))
        lines.append(f"Displayed: {shown} of {total}")
        lines.append(f"Saved Findings: {saved}")
        lines.append(f"Modules Succeeded: {summary.get('module_success_count', 0)}/{summary.get('module_count', 0)}")
        if summary.get("module_error_count"):
            lines.append(f"Module Failures: {summary['module_error_count']}")
        if summary.get("display_truncated"):
            lines.append("Display truncated for terminal readability; saved artifact contains the full filtered result set.")

    limitations = metadata.get("limitations") or []
    if limitations and not quiet:
        lines.append("")
        lines.append("Limitations:")
        for limitation in limitations:
            lines.append(f"- {limitation.get('message', 'Unknown limitation')}")

    if not results:
        lines.append("")
        lines.append("No findings matched the current filters.")
        lines.extend(_render_output_footer(metadata))
        return "\n".join(lines)

    lines.append("")
    by_severity = _group_findings_by_severity(results)
    for severity in SEVERITY_ORDER:
        findings = by_severity.get(severity, [])
        if not findings:
            continue

        lines.append(_severity_heading(severity, len(findings)))
        module_groups = _group_findings_by_module(findings)
        for module_name, module_findings in module_groups:
            lines.extend(_render_module_section(module_name, module_findings))
        lines.append("")

    lines.extend(_render_output_footer(metadata))
    return "\n".join(lines).rstrip()


def _render_analyze_finding(item: dict[str, Any]) -> list[str]:
    finding_id = item.get("finding_id", "TX-UNSET")
    path_value = item.get("path") or item.get("normalized_path") or "N/A"
    title = _display_finding_type(item)
    lines = [
        f"[{item.get('severity', 'INFO')}] {title}",
        f"ID: {finding_id}",
    ]
    user_value = _derive_user_label(item)
    if user_value:
        lines.append(f"User: {user_value}")
    lines.append(f"File: {path_value}")
    lines.append("")
    lines.append(f"Score: {item.get('score', 0)}")
    lines.append(f"Rule: {item.get('rule_id', 'TX-RULE-UNSET')}")
    lines.append(f"Reason: {item.get('reason', 'No reason provided')}")
    tags = _ensure_list(item.get("tags"))
    preview_lines = _render_preview_block(str(item["preview"])) if item.get("preview") else []
    if preview_lines:
        lines.append("")
        lines.extend(preview_lines)
    if tags:
        lines.append("")
        lines.append(f"Tags: {', '.join(tags)}")
    lines.append(SECTION_RULE)
    return lines


def _render_preview_block(preview: str, *, width: int = 96) -> list[str]:
    label, body = _format_preview_label_and_body(preview)
    wrapped = textwrap.wrap(
        body,
        width=width,
        break_long_words=False,
        break_on_hyphens=False,
    )
    if not wrapped:
        return [f"{label}:", "  [empty preview]"]
    lines = [f"{label}:"]
    lines.append(f"  {wrapped[0]}")
    lines.extend(f"    {line}" for line in wrapped[1:])
    return lines


def _render_collect_text(results: list[dict[str, Any]], metadata: dict[str, Any]) -> str:
    lines: list[str] = ["=== TENAX COLLECT RESULTS ==="]
    summary = metadata.get("summary", {})
    if summary:
        lines.append(f"Artifacts: {summary.get('artifact_count', len(results))}")
        lines.append(f"References: {summary.get('reference_count', 0)}")
        lines.append(f"Errors: {summary.get('error_count', 0)}")
    limitations = metadata.get("limitations") or []
    if limitations:
        lines.append("Limitations:")
        for limitation in limitations:
            lines.append(f"- {limitation.get('message', 'Unknown limitation')}")
    return "\n".join(lines)


def _group_findings_by_severity(results: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in results:
        grouped[str(item.get("severity", "INFO")).upper()].append(item)
    return grouped


def _group_findings_by_module(results: list[dict[str, Any]]) -> list[tuple[str, list[dict[str, Any]]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in results:
        grouped[str(item.get("source", "unknown"))].append(item)
    ordered = sorted(grouped.items(), key=lambda entry: entry[0])
    return [(name, items) for name, items in ordered]


def _render_severity_summary(summary: dict[str, Any]) -> list[str]:
    severity_counts = summary.get("severity_counts") or {}
    labels = {
        "CRITICAL": "🔥 CRITICAL FINDINGS",
        "HIGH": "HIGH FINDINGS",
        "MEDIUM": "MEDIUM FINDINGS",
        "LOW": "LOW FINDINGS",
        "INFO": "INFO FINDINGS",
    }
    lines: list[str] = []
    for severity in SEVERITY_ORDER:
        count = int(severity_counts.get(severity, 0))
        lines.append(f"{labels[severity]}: {count}")
    return lines


def _severity_heading(severity: str, count: int) -> str:
    labels = {
        "CRITICAL": f"🔥 CRITICAL FINDINGS: {count}",
        "HIGH": f"HIGH FINDINGS: {count}",
        "MEDIUM": f"MEDIUM FINDINGS: {count}",
        "LOW": f"LOW FINDINGS: {count}",
        "INFO": f"INFO FINDINGS: {count}",
    }
    return labels.get(severity, f"{severity} FINDINGS: {count}")


def _render_module_section(module_name: str, findings: list[dict[str, Any]]) -> list[str]:
    context = _module_context_from_items(findings)
    header = f"{str(module_name).upper()} ({context})"
    width = max(len(header) + 2, 44)
    top = "┌" + ("─" * width) + "┐"
    middle = "│ " + header.ljust(width - 1) + "│"
    bottom = "└" + ("─" * width) + "┘"
    lines = [top, middle, bottom, ""]
    for item in findings:
        lines.extend(_render_analyze_finding(item))
        lines.append("")
    if lines and not lines[-1].strip():
        lines.pop()
    return lines


def _module_context_from_items(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "ANALYSIS"
    scopes = {str(item.get("scope", "unknown")).lower() for item in findings}
    tags = {str(tag) for item in findings for tag in _ensure_list(item.get("tags"))}
    if "mixed" in scopes:
        return "MIXED SCOPE"
    if "user" in scopes:
        return "USER PERSISTENCE"
    if "system" in scopes:
        return "SYSTEM-LEVEL"
    if "user-persistence" in tags:
        return "USER PERSISTENCE"
    if "system-scope" in tags or "root-execution" in tags:
        return "SYSTEM-LEVEL"
    return "ANALYSIS"


def _display_finding_type(item: dict[str, Any]) -> str:
    rule_name = str(item.get("rule_name", "") or "").strip()
    if rule_name:
        return rule_name.upper()
    source = str(item.get("source", "unknown")).replace("_", " ")
    return f"{source} SUSPICIOUS PERSISTENCE ARTIFACT".upper()


def _derive_user_label(item: dict[str, Any]) -> str | None:
    path_value = str(item.get("path") or item.get("normalized_path") or "")
    home_match = re.search(r"/home/([^/]+)/", path_value)
    if home_match:
        return home_match.group(1)
    if path_value.startswith("/root/") or path_value == "/root":
        return "root"
    scope = str(item.get("scope", "")).lower()
    if scope == "system":
        return "system"
    return None


def _format_preview_label_and_body(preview: str) -> tuple[str, str]:
    preview = preview.strip()
    line_match = LINE_PREVIEW_REGEX.match(preview)
    if line_match:
        return "Exec", f"line {line_match.group(1)} -> {line_match.group(2)}"
    if preview.lower().startswith(("exec=", "execstart=", "command=")):
        return "Exec", preview
    return "Evidence", preview


def _render_output_footer(metadata: dict[str, Any]) -> list[str]:
    output_locations = metadata.get("output_locations") or {}
    saved_path = output_locations.get("saved")
    explicit_path = output_locations.get("explicit")
    if not saved_path:
        return []

    lines = [
        HEADER_RULE,
        "Output saved:",
        str(saved_path),
    ]
    if explicit_path:
        lines.append(str(explicit_path))
    lines.append(HEADER_RULE)
    return lines


def _ensure_list(value: Any) -> list[Any]:
    if not value:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _get_tenax_output_dir():
    return resolve_runtime_output_dir()
