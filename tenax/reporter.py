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


def render_text(
    mode: str,
    results: list[dict[str, Any]],
    metadata: dict[str, Any] | None = None,
) -> str:
    metadata = metadata or {}

    if mode == "analyze":
        return _render_analyze_text(results, metadata)

    return _render_collect_text(results)


def _render_analyze_text(
    results: list[dict[str, Any]],
    metadata: dict[str, Any],
) -> str:
    lines: list[str] = ["=== TENAX ANALYZE RESULTS ===", ""]

    summary = metadata.get("summary", {})
    filters = metadata.get("filters", {})

     if summary and not metadata.get("quiet", False):
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


def _render_collect_text(results: list[dict[str, Any]]) -> str:
    lines = ["=== TENAX COLLECT RESULTS ===", ""]

    if not results:
        lines.append("No results found.")
        return "\n".join(lines)

    for index, item in enumerate(results, start=1):
        source = str(item.get("source", "unknown")).replace("_", " ").upper()
        path_value = item.get("path", "N/A")

        lines.append("=" * 80)
        lines.append(f"[{index}] ## {source} ##")
        lines.append(f"Path: {path_value}")
        lines.append(f"Type: {item.get('type', 'artifact')}")
        lines.append(f"Exists: {item.get('exists', False)}")
        lines.append(f"Owner: {item.get('owner', 'unknown')}")
        lines.append(f"Permissions: {item.get('permissions', 'unknown')}")
        if item.get("sha256"):
            lines.append(f"SHA256: {item['sha256']}")
        lines.append("")

    return "\n".join(lines).rstrip()


def _render_summary_block(summary: dict[str, Any]) -> list[str]:
    lines = ["--- Summary ---"]

    ordered_summary_fields = [
        ("module_success_count", "Modules succeeded"),
        ("module_count", "Modules total"),
        ("module_error_count", "Modules failed"),
        ("raw_finding_count", "Raw findings"),
        ("consolidated_finding_count", "Consolidated findings"),
        ("deduplicated_count", "Duplicates collapsed"),
        ("unique_path_count", "Unique paths"),
        ("temp_path_finding_count", "Temp-path findings"),
        ("analysis_duration_ms", "Analysis duration (ms)"),
    ]

    for key, label in ordered_summary_fields:
        if key in summary:
            lines.append(f"{label}: {summary[key]}")

    severity_counts = summary.get("severity_counts", {})
    if severity_counts:
        rendered = ", ".join(
            f"{severity}={severity_counts.get(severity, 0)}" for severity in SEVERITY_ORDER
        )
        lines.append(f"Severity counts: {rendered}")

    source_counts = summary.get("source_counts", {})
    if source_counts:
        top_sources = list(source_counts.items())[:8]
        rendered = ", ".join(f"{source}={count}" for source, count in top_sources)
        lines.append(f"Top sources: {rendered}")

    top_tags = summary.get("top_tags", {})
    if top_tags:
        rendered = ", ".join(f"{tag}={count}" for tag, count in list(top_tags.items())[:10])
        lines.append(f"Top tags: {rendered}")

    errored_modules = summary.get("errored_modules", [])
    if errored_modules:
        lines.append("Module errors:")
        for entry in errored_modules:
            lines.append(f"  - {entry.get('source', 'unknown')}: {entry.get('error', 'Unknown error')}")

    return lines


def _render_filter_block(filters: dict[str, Any]) -> list[str]:
    lines = ["--- Active Filters ---"]
    for key in (
        "severity",
        "sources",
        "path_contains",
        "only_writable",
        "only_existing",
        "scope",
        "sort_by",
        "top",
    ):
        value = filters.get(key)
        if value in (None, [], False, ""):
            continue
        lines.append(f"{key}: {value}")
    return lines


def _group_findings_by_severity(
    results: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in results:
        severity = str(item.get("severity", "INFO")).upper()
        grouped[severity].append(item)
    return grouped


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
    lines.append(f"Reason: {item.get('reason', 'No reason provided')}")

    sources = item.get("sources")
    if sources:
        lines.append(f"Sources: {', '.join(_ensure_list_of_strings(sources))}")

    reasons = _ensure_list_of_strings(item.get("reasons"))
    if len(reasons) > 1:
        lines.append("All reasons:")
        for reason in reasons:
            lines.append(f"  - {reason}")

    tags = _ensure_list_of_strings(item.get("tags"))
    if tags:
        lines.append(f"Tags: {', '.join(tags)}")

    normalized_path = item.get("normalized_path")
    if normalized_path and normalized_path != path_value:
        lines.append(f"Normalized path: {normalized_path}")

    path_variants = _ensure_list_of_strings(item.get("path_variants"))
    if len(path_variants) > 1:
        lines.append(f"Path variants: {', '.join(path_variants)}")

    dedupe_count = item.get("dedupe_count")
    if dedupe_count and int(dedupe_count) > 1:
        lines.append(f"Merged hits: {dedupe_count}")

    score_breakdown = item.get("score_breakdown", {})
    if score_breakdown:
        lines.append(
            "Score breakdown: "
            f"max={score_breakdown.get('max_score', 0)}, "
            f"reasons={score_breakdown.get('reason_count', 0)}, "
            f"sources={score_breakdown.get('source_count', 0)}"
        )

    recommendation = _derive_triage_recommendation(item)
    if recommendation:
        lines.append(f"Triage next step: {recommendation}")

    if preview:
        lines.append(f"Preview: {preview}")

    return lines


def _derive_triage_recommendation(item: dict[str, Any]) -> str:
    tags = set(_ensure_list_of_strings(item.get("tags")))
    source = str(item.get("source", "")).lower()
    path_value = str(item.get("path", "")).lower()

    if "service-definition" in tags or source == "systemd":
        return "Inspect unit contents, ExecStart target, and service owner."
    if source == "cron" or source == "at_jobs":
        return "Validate schedule, command lineage, and referenced executables."
    if "ssh-persistence" in tags or path_value.endswith("authorized_keys"):
        return "Review key provenance, file ownership, and recent login history."
    if source == "sudoers":
        return "Validate delegation scope and confirm NOPASSWD necessity."
    if source == "pam":
        return "Inspect PAM module path and compare against known-good auth stack."
    if source == "ld_preload":
        return "Verify preload library path, ownership, and dependent processes."
    if "temp-path" in tags:
        return "Examine file contents, timestamps, and execution lineage from temp paths."
    if "network-retrieval" in tags:
        return "Check for download-and-execute behavior and outbound connection history."
    if "shell-execution" in tags:
        return "Review parent shell config and command provenance."
    return "Validate ownership, permissions, modification time, and execution context."


def _get_artifact_preview(path_value: str, max_length: int = 180) -> str | None:
    path = Path(path_value)
    try:
        if path.is_symlink():
            try:
                return f"symlink -> {path.resolve()}"
            except OSError:
                return "symlink target could not be resolved"

        if not path.exists():
            return None

        if path.is_dir():
            return "directory artifact"

        raw = path.read_bytes()
        if b"\x00" in raw[:4096]:
            return "[binary content omitted]"

        content = raw.decode("utf-8", errors="ignore")
        preview_line = _find_best_preview_line(content)
        if not preview_line:
            return None

        preview_line = " ".join(preview_line.split())
        if len(preview_line) > max_length:
            preview_line = preview_line[: max_length - 3] + "..."
        return preview_line
    except PermissionError:
        return "[preview unavailable: permission denied]"
    except OSError:
        return None


def _find_best_preview_line(content: str) -> str | None:
    lines = content.splitlines()

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for keyword in PREVIEW_KEYWORDS:
            if keyword in stripped:
                return stripped

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        return stripped

    return None


def _ensure_list_of_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        cleaned = value.strip()
        return [cleaned] if cleaned else []
    if isinstance(value, (list, tuple, set)):
        output: list[str] = []
        for item in value:
            if item is None:
                continue
            cleaned = str(item).strip()
            if cleaned:
                output.append(cleaned)
        return output
    cleaned = str(value).strip()
    return [cleaned] if cleaned else []