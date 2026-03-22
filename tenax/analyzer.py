from __future__ import annotations

import time
from collections import Counter
from pathlib import Path
from typing import Any, Callable

from tenax.checks.at_jobs import analyze_at_job_locations
from tenax.checks.autostart_hooks import analyze_autostart_hook_locations
from tenax.checks.capabilities import analyze_capabilities
from tenax.checks.containers import analyze_container_locations
from tenax.checks.cron import analyze_cron_locations
from tenax.checks.environment_hooks import analyze_environment_hook_locations
from tenax.checks.ld_preload import analyze_ld_preload_locations
from tenax.checks.network_hooks import analyze_network_hook_locations
from tenax.checks.pam import analyze_pam_locations
from tenax.checks.rc_init import analyze_rc_init_locations
from tenax.checks.shell_profiles import analyze_shell_profile_locations
from tenax.checks.ssh import analyze_ssh_locations
from tenax.checks.sudoers import analyze_sudoers_locations
from tenax.checks.systemd import analyze_systemd_locations
from tenax.checks.tmp_paths import analyze_tmp_paths
from tenax.reporter import output_results

MODULES: tuple[tuple[str, Callable[[], list[dict[str, Any]]]], ...] = (
    ("cron", analyze_cron_locations),
    ("systemd", analyze_systemd_locations),
    ("shell_profiles", analyze_shell_profile_locations),
    ("ssh", analyze_ssh_locations),
    ("sudoers", analyze_sudoers_locations),
    ("rc_init", analyze_rc_init_locations),
    ("tmp_paths", analyze_tmp_paths),
    ("ld_preload", analyze_ld_preload_locations),
    ("autostart_hooks", analyze_autostart_hook_locations),
    ("network_hooks", analyze_network_hook_locations),
    ("pam", analyze_pam_locations),
    ("at_jobs", analyze_at_job_locations),
    ("containers", analyze_container_locations),
    ("environment_hooks", analyze_environment_hook_locations),
    ("capabilities", analyze_capabilities),
)

SOURCE_PRIORITY: dict[str, int] = {
    "systemd": 100,
    "ld_preload": 95,
    "pam": 90,
    "sudoers": 88,
    "ssh": 86,
    "cron": 84,
    "at_jobs": 82,
    "rc_init": 80,
    "autostart_hooks": 78,
    "shell_profiles": 76,
    "network_hooks": 74,
    "environment_hooks": 72,
    "capabilities": 70,
    "containers": 68,
    "tmp_paths": 66,
}

SEVERITY_RANK: dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

TEMP_PATH_PREFIXES = ("/tmp", "/var/tmp", "/dev/shm")
SYSTEM_PATH_PREFIXES = (
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/opt",
    "/var",
    "/boot",
    "/run",
)
USER_SCOPE_MARKERS = (
    "/home/",
    "/root/",
    ".bashrc",
    ".profile",
    ".zshrc",
    ".config/autostart",
    "authorized_keys",
)

SUSPICIOUS_KEYWORDS: dict[str, str] = {
    "curl": "network-retrieval",
    "wget": "network-retrieval",
    "fetch": "network-retrieval",
    "scp ": "network-retrieval",
    "ftp ": "network-retrieval",
    "tftp ": "network-retrieval",
    "nc ": "network-retrieval",
    "ncat": "network-retrieval",
    "socat": "network-retrieval",
    "bash -c": "shell-execution",
    "sh -c": "shell-execution",
    "python -c": "shell-execution",
    "perl -e": "shell-execution",
    "nohup": "detached-execution",
    "setsid": "detached-execution",
    "base64": "encoded-payload",
    "mkfifo": "pipe-staging",
    "ld_preload": "preload-hook",
    "execstart=": "service-exec",
    "exec=": "service-exec",
    "hidden=true": "hidden-autostart",
    "nopasswd": "sudo-trust",
    "all=(all)": "broad-sudo",
    "all=(all:all)": "broad-sudo",
    "authorized_keys": "ssh-persistence",
    "pam": "auth-hook",
    "cap_": "capabilities",
    "docker": "container-hook",
    "podman": "container-hook",
}


def _safe_invoke_module(
    source: str,
    func: Callable[[], list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    start = time.perf_counter()
    try:
        results = func()
        if results is None:
            results = []
        if not isinstance(results, list):
            raise TypeError(
                f"Module '{source}' returned {type(results).__name__}; expected list[dict]."
            )
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        return results, {
            "source": source,
            "status": "ok",
            "duration_ms": duration_ms,
            "finding_count": len(results),
        }
    except Exception as exc:  # pragma: no cover
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        return [], {
            "source": source,
            "status": "error",
            "duration_ms": duration_ms,
            "finding_count": 0,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _coerce_score(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _normalize_severity(value: Any, score: int) -> str:
    if isinstance(value, str):
        candidate = value.strip().upper()
        if candidate in SEVERITY_RANK:
            return candidate

    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "INFO"


def _normalize_path(path_value: Any) -> str | None:
    if not path_value:
        return None

    path_str = str(path_value).strip()
    if not path_str:
        return None

    try:
        return str(Path(path_str).expanduser().resolve(strict=False))
    except Exception:
        return path_str


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


def _pick_primary_source(sources: list[str]) -> str:
    if not sources:
        return "unknown"
    return max(
        sorted(set(sources)),
        key=lambda source: SOURCE_PRIORITY.get(source, 0),
    )


def _pick_strongest_severity(severities: list[str]) -> str:
    if not severities:
        return "INFO"
    return max(
        sorted(set(severities)),
        key=lambda sev: SEVERITY_RANK.get(sev, 0),
    )


def _contains_any(text: str, values: tuple[str, ...]) -> bool:
    return any(value in text for value in values)


def _derive_tags(
    source: str,
    path_value: str | None,
    reason: str,
    preview: str,
) -> list[str]:
    tags: set[str] = set()
    combined = f"{reason}\n{preview}\n{path_value or ''}".lower()

    tags.add(source.replace("_", "-"))

    if source in {"systemd", "pam", "sudoers", "ld_preload"}:
        tags.add("root-execution")
    if source in {"cron", "at_jobs", "systemd", "rc_init", "autostart_hooks"}:
        tags.add("scheduled-start")
    if source in {"ssh", "shell_profiles", "autostart_hooks", "environment_hooks"}:
        tags.add("user-persistence")

    if path_value:
        path_lower = path_value.lower()

        if path_lower.startswith(TEMP_PATH_PREFIXES):
            tags.update({"temp-path", "suspicious-location"})
        if path_lower.startswith("/etc/systemd") or "/systemd/" in path_lower:
            tags.add("service-definition")
        if path_lower.endswith("authorized_keys"):
            tags.update({"ssh-persistence", "credential-surface"})
        if path_lower.endswith(".desktop"):
            tags.add("autostart-entry")
        if _contains_any(path_lower, USER_SCOPE_MARKERS):
            tags.add("user-scope")
        if path_lower.startswith(SYSTEM_PATH_PREFIXES):
            tags.add("system-scope")
        if path_lower.startswith("/usr/local/bin") or path_lower.startswith("/usr/local/sbin"):
            tags.add("local-binary-path")
        if path_lower.endswith((".service", ".timer", ".socket", ".mount", ".path", ".target")):
            tags.add("systemd-unit")

    for keyword, tag in SUSPICIOUS_KEYWORDS.items():
        if keyword in combined:
            tags.add(tag)

    if "world-writable" in combined or "writable by everyone" in combined:
        tags.add("world-writable")
    if "group-writable" in combined:
        tags.add("group-writable")
    if "writable" in combined:
        tags.add("writable")
    if "symlink" in combined:
        tags.add("symlink")
    if "hidden" in combined:
        tags.add("hidden")
    if "base64" in combined:
        tags.add("obfuscated")
    if "tmp-paths" in tags:
        tags.add("temp-path")

    return sorted(tags)


def _enrich_result(source: str, item: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(item)

    score = _coerce_score(enriched.get("score", 0))
    severity = _normalize_severity(enriched.get("severity"), score)

    path_value = enriched.get("path")
    normalized_path = _normalize_path(path_value)

    reason = str(enriched.get("reason", "") or "").strip()
    preview = str(enriched.get("preview", "") or "").strip()
    tags = _derive_tags(
        source=source,
        path_value=str(path_value) if path_value is not None else None,
        reason=reason,
        preview=preview,
    )

    enriched["source"] = source
    enriched["score"] = score
    enriched["severity"] = severity
    enriched["normalized_path"] = normalized_path
    enriched["reason"] = reason or "No reason provided"
    if preview:
        enriched["preview"] = preview
    enriched["tags"] = sorted(set(_ensure_list_of_strings(enriched.get("tags"))) | set(tags))
    return enriched


def _merge_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}

    for item in findings:
        normalized_path = item.get("normalized_path")
        source = str(item.get("source", "unknown"))
        reason = str(item.get("reason", "No reason provided"))
        preview = str(item.get("preview", ""))

        if normalized_path:
            key = f"path::{normalized_path}"
        else:
            key = f"fallback::{source}::{reason}::{preview}"

        if key not in merged:
            merged[key] = {
                **item,
                "sources": [source],
                "reasons": [reason],
                "tags": _ensure_list_of_strings(item.get("tags")),
                "severity_candidates": [str(item.get("severity", "INFO"))],
                "raw_scores": [_coerce_score(item.get("score", 0))],
                "dedupe_count": 1,
                "path_variants": [str(item.get("path"))] if item.get("path") else [],
            }
            continue

        current = merged[key]
        current["dedupe_count"] += 1
        current["sources"] = sorted(
            set(_ensure_list_of_strings(current.get("sources"))) | {source}
        )
        current["reasons"] = sorted(
            set(_ensure_list_of_strings(current.get("reasons"))) | {reason}
        )
        current["tags"] = sorted(
            set(_ensure_list_of_strings(current.get("tags")))
            | set(_ensure_list_of_strings(item.get("tags")))
        )
        current["severity_candidates"] = _ensure_list_of_strings(
            current.get("severity_candidates")
        ) + [str(item.get("severity", "INFO"))]
        current["raw_scores"] = list(current.get("raw_scores", [])) + [
            _coerce_score(item.get("score", 0))
        ]

        if item.get("path"):
            current["path_variants"] = sorted(
                set(_ensure_list_of_strings(current.get("path_variants")))
                | {str(item.get("path"))}
            )

        if _coerce_score(item.get("score", 0)) > _coerce_score(current.get("score", 0)):
            current["score"] = _coerce_score(item.get("score", 0))
            current["reason"] = reason
            if item.get("preview"):
                current["preview"] = item["preview"]
            if item.get("path"):
                current["path"] = item["path"]

        if not current.get("preview") and item.get("preview"):
            current["preview"] = item["preview"]

    consolidated: list[dict[str, Any]] = []

    for item in merged.values():
        sources = sorted(set(_ensure_list_of_strings(item.get("sources"))))
        reasons = sorted(set(_ensure_list_of_strings(item.get("reasons"))))
        tags = sorted(set(_ensure_list_of_strings(item.get("tags"))))
        severities = _ensure_list_of_strings(item.get("severity_candidates"))
        raw_scores = [_coerce_score(value) for value in item.get("raw_scores", [])]

        primary_source = _pick_primary_source(sources)
        strongest_severity = _pick_strongest_severity(severities)
        max_score = max(raw_scores) if raw_scores else _coerce_score(item.get("score", 0))

        consolidated_item = {
            **item,
            "source": primary_source,
            "sources": sources,
            "reason": item.get("reason") or (reasons[0] if reasons else "No reason provided"),
            "reasons": reasons,
            "score": max_score,
            "severity": strongest_severity,
            "tags": tags,
            "score_breakdown": {
                "max_score": max_score,
                "raw_scores": raw_scores,
                "reason_count": len(reasons),
                "source_count": len(sources),
            },
            "normalized_path": item.get("normalized_path"),
        }
        consolidated.append(consolidated_item)

    return consolidated


def _sort_key(item: dict[str, Any], sort_by: str = "score") -> tuple[Any, ...]:
    score = _coerce_score(item.get("score", 0))
    severity_rank = SEVERITY_RANK.get(str(item.get("severity", "INFO")), 0)
    source_priority = SOURCE_PRIORITY.get(str(item.get("source", "unknown")), 0)
    tags = set(_ensure_list_of_strings(item.get("tags")))
    path_value = str(item.get("path", "") or "").lower()
    source = str(item.get("source", "unknown")).lower()

    temp_bias = 1 if "temp-path" in tags else 0
    writable_bias = 1 if "writable" in tags or "world-writable" in tags else 0
    root_exec_bias = 1 if "root-execution" in tags else 0
    multi_reason_bias = len(_ensure_list_of_strings(item.get("reasons")))

    if sort_by == "severity":
        return (
            severity_rank,
            score,
            root_exec_bias,
            writable_bias,
            temp_bias,
            multi_reason_bias,
            source_priority,
            path_value,
        )
    if sort_by == "path":
        return (
            path_value,
            score,
            severity_rank,
            source_priority,
        )
    if sort_by == "source":
        return (
            source,
            score,
            severity_rank,
            path_value,
        )

    return (
        score,
        severity_rank,
        root_exec_bias,
        writable_bias,
        temp_bias,
        multi_reason_bias,
        source_priority,
        path_value,
    )


def _assign_finding_ids(findings: list[dict[str, Any]]) -> None:
    counters: Counter[str] = Counter()
    for item in findings:
        source = str(item.get("source", "unknown")).upper().replace("-", "_")
        counters[source] += 1
        item["finding_id"] = f"TX-{source}-{counters[source]:04d}"


def _build_summary(
    raw_findings: list[dict[str, Any]],
    consolidated_findings: list[dict[str, Any]],
    module_status: list[dict[str, Any]],
    started_at: float,
) -> dict[str, Any]:
    severity_counts = Counter(
        str(item.get("severity", "INFO")) for item in consolidated_findings
    )
    source_counts = Counter(str(item.get("source", "unknown")) for item in consolidated_findings)
    tag_counts = Counter(
        tag for item in consolidated_findings for tag in _ensure_list_of_strings(item.get("tags"))
    )

    unique_paths = {
        item.get("normalized_path")
        for item in consolidated_findings
        if item.get("normalized_path")
    }

    temp_hits = sum(
        1
        for item in consolidated_findings
        if "temp-path" in set(_ensure_list_of_strings(item.get("tags")))
    )

    errored_modules = [entry for entry in module_status if entry.get("status") == "error"]
    ok_modules = [entry for entry in module_status if entry.get("status") == "ok"]

    return {
        "generated_epoch": round(time.time(), 3),
        "analysis_duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
        "module_count": len(module_status),
        "module_success_count": len(ok_modules),
        "module_error_count": len(errored_modules),
        "raw_finding_count": len(raw_findings),
        "consolidated_finding_count": len(consolidated_findings),
        "deduplicated_count": max(len(raw_findings) - len(consolidated_findings), 0),
        "unique_path_count": len(unique_paths),
        "temp_path_finding_count": temp_hits,
        "severity_counts": dict(sorted(severity_counts.items())),
        "source_counts": dict(source_counts.most_common()),
        "top_tags": dict(tag_counts.most_common(10)),
        "module_status": module_status,
        "errored_modules": errored_modules,
    }


def _print_module_summary(summary: dict[str, Any]) -> None:
    print("\n=== TENAX ANALYZE SUMMARY ===")
    print(f"Modules executed:      {summary['module_success_count']}/{summary['module_count']}")
    print(f"Module failures:       {summary['module_error_count']}")
    print(f"Raw findings:          {summary['raw_finding_count']}")
    print(f"Consolidated findings: {summary['consolidated_finding_count']}")
    print(f"Duplicates collapsed:  {summary['deduplicated_count']}")
    print(f"Unique paths:          {summary['unique_path_count']}")
    print(f"Temp path findings:    {summary['temp_path_finding_count']}")
    print(f"Scan duration:         {summary['analysis_duration_ms']} ms")

    severity_counts = summary.get("severity_counts", {})
    if severity_counts:
        ordered = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        rendered = " | ".join(
            f"{severity}={severity_counts.get(severity, 0)}" for severity in ordered
        )
        print(f"Severity counts:       {rendered}")

    source_counts = summary.get("source_counts", {})
    if source_counts:
        top_sources = list(source_counts.items())[:5]
        rendered = ", ".join(f"{source}={count}" for source, count in top_sources)
        print(f"Top sources:           {rendered}")

    top_tags = summary.get("top_tags", {})
    if top_tags:
        rendered = ", ".join(f"{tag}={count}" for tag, count in list(top_tags.items())[:8])
        print(f"Top tags:              {rendered}")

    if summary.get("errored_modules"):
        print("\n=== MODULE ERRORS ===")
        for entry in summary["errored_modules"]:
            print(f"- {entry['source']}: {entry.get('error', 'Unknown error')}")

    print("")


def _matches_source_filter(item: dict[str, Any], allowed_sources: set[str] | None) -> bool:
    if not allowed_sources:
        return True
    item_sources = {
        source.strip().lower()
        for source in _ensure_list_of_strings(item.get("sources") or item.get("source"))
    }
    return bool(item_sources & allowed_sources)


def _matches_severity_filter(item: dict[str, Any], minimum_severity: str | None) -> bool:
    if not minimum_severity:
        return True
    threshold = SEVERITY_RANK[minimum_severity]
    item_rank = SEVERITY_RANK.get(str(item.get("severity", "INFO")), 0)
    return item_rank >= threshold


def _matches_path_filter(item: dict[str, Any], path_contains: str | None) -> bool:
    if not path_contains:
        return True
    needle = path_contains.lower()
    path_value = str(item.get("path", "") or "").lower()
    normalized_path = str(item.get("normalized_path", "") or "").lower()
    return needle in path_value or needle in normalized_path


def _matches_writable_filter(item: dict[str, Any], only_writable: bool) -> bool:
    if not only_writable:
        return True
    tags = set(_ensure_list_of_strings(item.get("tags")))
    return bool({"writable", "world-writable", "group-writable"} & tags)


def _matches_existing_filter(item: dict[str, Any], only_existing: bool) -> bool:
    if not only_existing:
        return True
    path_value = item.get("path")
    if not path_value:
        return False
    try:
        return Path(str(path_value)).expanduser().exists()
    except OSError:
        return False


def _matches_scope_filter(item: dict[str, Any], scope: str | None) -> bool:
    if not scope:
        return True
    tags = set(_ensure_list_of_strings(item.get("tags")))
    if scope == "user":
        return "user-scope" in tags
    if scope == "system":
        return "system-scope" in tags
    return True


def _apply_filters(
    findings: list[dict[str, Any]],
    severity: str | None = None,
    sources: list[str] | None = None,
    path_contains: str | None = None,
    only_writable: bool = False,
    only_existing: bool = False,
    scope: str | None = None,
) -> list[dict[str, Any]]:
    allowed_sources = {source.strip().lower() for source in (sources or []) if source.strip()}
    minimum_severity = severity.upper() if severity else None

    filtered: list[dict[str, Any]] = []
    for item in findings:
        if not _matches_source_filter(item, allowed_sources):
            continue
        if not _matches_severity_filter(item, minimum_severity):
            continue
        if not _matches_path_filter(item, path_contains):
            continue
        if not _matches_writable_filter(item, only_writable):
            continue
        if not _matches_existing_filter(item, only_existing):
            continue
        if not _matches_scope_filter(item, scope):
            continue
        filtered.append(item)
    return filtered


def run_analysis(
    output_path=None,
    output_format: str = "text",
    top: int = 20,
    severity: str | None = None,
    sources: list[str] | None = None,
    path_contains: str | None = None,
    only_writable: bool = False,
    only_existing: bool = False,
    scope: str | None = None,
    sort_by: str = "score",
    quiet: bool = False,
    verbose: bool = False,
) -> None:
    started_at = time.perf_counter()

    raw_findings: list[dict[str, Any]] = []
    module_status: list[dict[str, Any]] = []

    for source, func in MODULES:
        results, status = _safe_invoke_module(source, func)
        if status:
            module_status.append(status)
            if verbose and not quiet:
                status_line = (
                    f"[module] {source}: status={status['status']} "
                    f"findings={status['finding_count']} duration_ms={status['duration_ms']}"
                )
                if status.get("error"):
                    status_line += f" error={status['error']}"
                print(status_line)

        for item in results:
            if not isinstance(item, dict):
                continue
            raw_findings.append(_enrich_result(source, item))

    consolidated_findings = _merge_findings(raw_findings)

    for item in consolidated_findings:
        item["score"] = _coerce_score(item.get("score", 0))
        item["severity"] = _normalize_severity(item.get("severity"), item["score"])

    consolidated_findings = _apply_filters(
        findings=consolidated_findings,
        severity=severity,
        sources=sources,
        path_contains=path_contains,
        only_writable=only_writable,
        only_existing=only_existing,
        scope=scope,
    )

    reverse_sort = sort_by != "path"
    consolidated_findings.sort(
        key=lambda item: _sort_key(item, sort_by=sort_by),
        reverse=reverse_sort,
    )

    _assign_finding_ids(consolidated_findings)

    if top is not None and top >= 0:
        consolidated_findings = consolidated_findings[:top]

    summary = _build_summary(
        raw_findings=raw_findings,
        consolidated_findings=consolidated_findings,
        module_status=module_status,
        started_at=started_at,
    )

    metadata = {
        "mode": "analyze",
        "quiet": quiet,
        "filters": {
            "severity": severity,
            "sources": sources or [],
            "path_contains": path_contains,
            "only_writable": only_writable,
            "only_existing": only_existing,
            "scope": scope,
            "sort_by": sort_by,
            "top": top,
        },
        "summary": summary,
    }

    output_results(
        mode="analyze",
        results=consolidated_findings,
        output_format=output_format,
        output_path=output_path,
        metadata=metadata,
    )