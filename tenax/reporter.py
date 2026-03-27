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
    *,
    display_results: list[dict[str, Any]] | None = None,
) -> None:
    metadata = metadata or {}
    saved_results = results
    terminal_results = display_results if display_results is not None else results

    output_dir = _get_tenax_output_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    extension = "json" if output_format == "json" else "txt"
    auto_output_file = output_dir / f"{mode}_{timestamp}.{extension}"

    explicit_output_file = None
    if output_path:
        output_path = Path(output_path)
        explicit_output_file = output_path / f"{mode}_{timestamp}.{extension}" if output_path.is_dir() else output_path

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

    terminal_render = _render(mode, terminal_results, output_format, terminal_metadata)
    print(terminal_render)
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
    lines: list[str] = ["=== TENAX ANALYZE RESULTS ==="]
    summary = metadata.get("summary", {})
    quiet = bool(metadata.get("quiet", False))

    if summary and not quiet:
        total = summary.get("filtered_finding_count", len(results))
        shown = summary.get("displayed_finding_count", len(results))
        saved = summary.get("saved_finding_count", total)
        lines.append(f"Findings shown in terminal: {shown} of {total}")
        lines.append(f"Full findings saved: {saved}")
        lines.append(
            f"Modules: {summary.get('module_success_count', 0)}/{summary.get('module_count', 0)} succeeded"
        )
        if summary.get("module_error_count"):
            lines.append(f"Module failures: {summary['module_error_count']}")
        if summary.get("display_truncated"):
            lines.append("Display truncated for terminal readability; saved artifact contains the full filtered result set.")

    limitations = metadata.get("limitations") or []
    if limitations and not quiet:
        lines.append("Limitations:")
        for limitation in limitations:
            lines.append(f"- {limitation.get('message', 'Unknown limitation')}")

    if not results:
        lines.append("No findings matched the current filters.")
        return "\n".join(lines)

    lines.append("")
    grouped = _group_findings_by_severity(results)
    for severity in SEVERITY_ORDER:
        findings = grouped.get(severity, [])
        if not findings:
            continue

        lines.append(f"{severity} ({len(findings)})")
        for item in findings:
            lines.extend(_render_analyze_finding(item))
        lines.append("")

    return "\n".join(lines).rstrip()


def _render_analyze_finding(item: dict[str, Any]) -> list[str]:
    finding_id = item.get("finding_id", "TX-UNSET")
    path_value = item.get("path") or item.get("normalized_path") or "N/A"
    source = str(item.get("source", "unknown"))
    lines = [
        f"{finding_id} {item.get('severity', 'INFO')} {source} {path_value}",
        f"  score={item.get('score', 0)} rule={item.get('rule_id', 'TX-RULE-UNSET')}",
        f"  reason={item.get('reason', 'No reason provided')}",
    ]
    tags = _ensure_list(item.get("tags"))
    if tags:
        lines.append(f"  tags={', '.join(tags)}")
    if item.get("preview"):
        lines.append(f"  preview={item['preview']}")
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


def _ensure_list(value: Any) -> list[Any]:
    if not value:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _get_tenax_output_dir() -> Path:
    repo_root = _find_project_root()
    output_dir = repo_root / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def _find_project_root() -> Path:
    for start in (Path.cwd().resolve(), Path(__file__).resolve()):
        candidate = _find_repo_root_from(start)
        if candidate is not None:
            return candidate

    return Path.cwd().resolve()


def _find_repo_root_from(start: Path) -> Path | None:
    markers = ("pyproject.toml", "README.md")

    for candidate in (start, *start.parents):
        if "site-packages" in candidate.parts or "dist-packages" in candidate.parts:
            continue
        if all((candidate / marker).exists() for marker in markers) and (candidate / "tenax").is_dir():
            return candidate

    return None
