from __future__ import annotations

import hashlib
import time
from collections import Counter
from pathlib import Path
from time import perf_counter
from typing import Any, Callable

from tenax.checks import ANALYZE_SOURCES, BUILTIN_MODULES
from tenax.module_interface import apply_scoring_profile, determine_environment_label
from tenax.reporter import output_results
from tenax.scope import apply_module_scope, build_scan_scope, normalize_path_string

FINDING_SCHEMA_VERSION = "1.1"

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
    *,
    module_metadata: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
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
        module_limitations = getattr(func, "_tenax_limitations", [])
        return results, {
            "source": source,
            "status": "ok",
            "ok": True,
            "duration_ms": duration_ms,
            "finding_count": len(results),
            "module_metadata": module_metadata or {},
            "limitations": module_limitations,
        }
    except Exception as exc:  # pragma: no cover
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        return [], {
            "source": source,
            "status": "error",
            "ok": False,
            "duration_ms": duration_ms,
            "finding_count": 0,
            "error": f"{type(exc).__name__}: {exc}",
            "module_metadata": module_metadata or {},
            "limitations": getattr(func, "_tenax_limitations", []),
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

    return normalize_path_string(path_str)


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
    return max(sorted(set(sources)), key=lambda source: SOURCE_PRIORITY.get(source, 0))


def _pick_strongest_severity(severities: list[str]) -> str:
    if not severities:
        return "INFO"
    return max(sorted(set(severities)), key=lambda sev: SEVERITY_RANK.get(sev, 0))


def _contains_any(text: str, values: tuple[str, ...]) -> bool:
    return any(value in text for value in values)


def _derive_scope(tags: list[str]) -> str:
    tag_set = set(tags)
    if "user-scope" in tag_set and "system-scope" in tag_set:
        return "mixed"
    if "user-scope" in tag_set:
        return "user"
    if "system-scope" in tag_set:
        return "system"
    return "unknown"


def _derive_tags(
    source: str,
    path_value: str | None,
    reason: str,
    preview: str,
) -> list[str]:
    tags: set[str] = set()
    combined = f"{reason}\n{preview}\n{path_value or ''}".lower()

    tags.add(source.replace("_", "-"))

    if source in {"pam", "sudoers", "ld_preload"}:
        tags.add("root-execution")
    if source in {"cron", "at_jobs", "systemd", "rc_init", "autostart_hooks"}:
        tags.add("scheduled-start")
    if source in {"ssh", "shell_profiles", "autostart_hooks", "environment_hooks"}:
        tags.add("user-persistence")

    if path_value:
        path_lower = str(path_value).lower()

        if path_lower.startswith(TEMP_PATH_PREFIXES):
            tags.update({"temp-path", "suspicious-location"})
        if path_lower.startswith("/etc/systemd") or "/systemd/" in path_lower:
            tags.add("service-definition")
        if "/systemd/user/" in path_lower or "/.config/systemd/user/" in path_lower:
            tags.add("user-scope")
        if path_lower.endswith("authorized_keys"):
            tags.update({"ssh-persistence", "credential-surface"})
        if path_lower.endswith(".desktop"):
            tags.add("autostart-entry")
        if _contains_any(path_lower, USER_SCOPE_MARKERS):
            tags.add("user-scope")
        if path_lower.startswith(SYSTEM_PATH_PREFIXES) and "/systemd/user/" not in path_lower:
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


def _finding_identity(source: str, normalized_path: str | None, reason: str) -> str:
    basis = f"{source}|{normalized_path or ''}|{reason}"
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:12]


def _build_rule_id(source: str, tags: list[str]) -> str:
    interesting_tags = [tag.upper().replace("-", "_") for tag in tags if tag not in {source, source.replace("_", "-")}]
    suffix = interesting_tags[0] if interesting_tags else "GENERAL"
    return f"TX-RULE-{source.upper()}-{suffix}"


def _build_rule_name(source: str, tags: list[str]) -> str:
    source_label = source.replace("_", " ")
    if "world-writable" in tags:
        return f"{source_label} writable persistence surface"
    if "temp-path" in tags:
        return f"{source_label} temporary-path execution"
    if "preload-hook" in tags:
        return f"{source_label} preload hijack behavior"
    if "shell-execution" in tags:
        return f"{source_label} inline shell execution behavior"
    if "network-retrieval" in tags:
        return f"{source_label} network retrieval behavior"
    if "service-definition" in tags:
        return f"{source_label} service definition anomaly"
    return f"{source_label} suspicious persistence artifact"


def _build_rationale(
    *,
    source: str,
    primary_reason: str,
    reasons: list[str],
    preview: str | None,
    tags: list[str],
    normalized_path: str | None,
    paths: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "summary": primary_reason,
        "source": source,
        "reasons": reasons,
        "evidence_preview": preview,
        "tags": tags,
        "primary_path": normalized_path,
        "paths": paths or ([normalized_path] if normalized_path else []),
    }


def _enrich_result(source: str, item: dict[str, Any], *, scope_context=None) -> dict[str, Any]:
    enriched = dict(item)

    host_path = _normalize_path(enriched.get("path"))
    target_path = scope_context.target_path_from_host(host_path) if scope_context else host_path
    normalized_path = _normalize_path(target_path)
    module = BUILTIN_MODULES.get(source)
    environment = determine_environment_label(
        target_path,
        root_prefix=scope_context.root_prefix if scope_context else None,
    )
    score = apply_scoring_profile(_coerce_score(enriched.get("score", 0)), module, environment=environment)
    severity = _normalize_severity(enriched.get("severity"), score)
    reason = str(enriched.get("reason", "") or "").strip() or "No reason provided"
    preview = str(enriched.get("preview", "") or "").strip()
    tags = sorted(
        set(_ensure_list_of_strings(enriched.get("tags")))
        | set(_derive_tags(source=source, path_value=target_path, reason=reason, preview=preview))
    )
    scope = _derive_scope(tags)

    if target_path:
        enriched["path"] = target_path
        enriched["target_path"] = target_path
    if host_path and host_path != target_path:
        enriched["host_path"] = host_path
    enriched["source"] = source
    enriched["source_module"] = source
    enriched["score"] = score
    enriched["severity"] = severity
    enriched["normalized_path"] = normalized_path
    enriched["reason"] = reason
    if preview:
        enriched["preview"] = preview
    enriched["tags"] = tags
    enriched["scope"] = scope
    enriched["module_contract"] = module.metadata.analyze_contract if module else "list[finding]"
    enriched["heuristic_mode"] = module.metadata.heuristic_profile.default_mode if module else "strict"
    enriched["scoring_profile"] = module.metadata.scoring_profile.name if module else "default"
    enriched["rule_id"] = _build_rule_id(source, tags)
    enriched["rule_name"] = _build_rule_name(source, tags)
    enriched["schema_version"] = FINDING_SCHEMA_VERSION
    enriched["finding_key"] = _finding_identity(source, normalized_path, reason)
    enriched["rationale"] = _build_rationale(
        source=source,
        primary_reason=reason,
        reasons=_ensure_list_of_strings(enriched.get("reasons")) or [reason],
        preview=preview or None,
        tags=tags,
        normalized_path=normalized_path,
        paths=_ensure_list_of_strings(enriched.get("path")),
    )
    return enriched


def _merge_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}

    for item in findings:
        normalized_path = item.get("normalized_path")
        source = str(item.get("source", "unknown"))
        item_reason = str(item.get("reason", "No reason provided"))
        item_reasons = _ensure_list_of_strings(item.get("reasons")) or [item_reason]
        preview = str(item.get("preview", ""))

        rule_context = str(item.get("rule_id") or source)

        if normalized_path:
            key = f"path::{normalized_path}::rule::{rule_context}"
        else:
            key = f"fallback::{source}::{rule_context}::{item_reason}::{preview}"

        if key not in merged:
            merged[key] = {
                **item,
                "sources": [source],
                "reasons": item_reasons[:],
                "tags": _ensure_list_of_strings(item.get("tags")),
                "severity_candidates": [str(item.get("severity", "INFO"))],
                "raw_scores": [_coerce_score(item.get("score", 0))],
                "dedupe_count": 1,
                "path_variants": [str(item.get("path"))] if item.get("path") else [],
                "rule_ids": [str(item.get("rule_id", ""))] if item.get("rule_id") else [],
                "rule_names": [str(item.get("rule_name", ""))] if item.get("rule_name") else [],
            }
            continue

        current = merged[key]
        current["dedupe_count"] += 1
        current["sources"] = sorted(set(_ensure_list_of_strings(current.get("sources"))) | {source})
        current["reasons"] = sorted(set(_ensure_list_of_strings(current.get("reasons"))) | set(item_reasons))
        current["tags"] = sorted(
            set(_ensure_list_of_strings(current.get("tags")))
            | set(_ensure_list_of_strings(item.get("tags")))
        )
        current["severity_candidates"] = _ensure_list_of_strings(current.get("severity_candidates")) + [
            str(item.get("severity", "INFO"))
        ]
        current["raw_scores"] = list(current.get("raw_scores", [])) + [_coerce_score(item.get("score", 0))]
        current["rule_ids"] = sorted(
            set(_ensure_list_of_strings(current.get("rule_ids")))
            | set(_ensure_list_of_strings(item.get("rule_id")))
        )
        current["rule_names"] = sorted(
            set(_ensure_list_of_strings(current.get("rule_names")))
            | set(_ensure_list_of_strings(item.get("rule_name")))
        )

        if item.get("path"):
            current["path_variants"] = sorted(
                set(_ensure_list_of_strings(current.get("path_variants"))) | {str(item.get("path"))}
            )

        if _coerce_score(item.get("score", 0)) > _coerce_score(current.get("score", 0)):
            current["score"] = _coerce_score(item.get("score", 0))
            current["reason"] = item_reason
            current["source"] = source
            current["source_module"] = source
            current["rule_id"] = item.get("rule_id")
            current["rule_name"] = item.get("rule_name")
            current["finding_key"] = item.get("finding_key")
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
        normalized_path = item.get("normalized_path")
        primary_reason = item.get("reason") or (reasons[0] if reasons else "No reason provided")
        scope = _derive_scope(tags)
        rule_id = item.get("rule_id") or _build_rule_id(primary_source, tags)
        rule_name = item.get("rule_name") or _build_rule_name(primary_source, tags)

        path_values = sorted(
            set(_ensure_list_of_strings(item.get("path_variants")))
            | set(_ensure_list_of_strings(item.get("path")))
        )

        consolidated_item = {
            **item,
            "schema_version": FINDING_SCHEMA_VERSION,
            "source": primary_source,
            "source_module": primary_source,
            "sources": sources,
            "reason": primary_reason,
            "reasons": reasons,
            "score": max_score,
            "severity": strongest_severity,
            "tags": tags,
            "scope": scope,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "score_breakdown": {
                "max_score": max_score,
                "raw_scores": raw_scores,
                "reason_count": len(reasons),
                "source_count": len(sources),
            },
            "normalized_path": normalized_path,
            "paths": path_values,
            "evidence": {
                "preview": item.get("preview"),
                "reasons": reasons,
                "paths": path_values,
            },
            "dedupe": {
                "merged_count": int(item.get("dedupe_count", 1)),
                "sources": sources,
                "rule_ids": sorted(
                    set(_ensure_list_of_strings(item.get("rule_ids")))
                    | set(_ensure_list_of_strings(rule_id))
                ),
            },
            "finding_key": item.get("finding_key") or _finding_identity(primary_source, normalized_path, primary_reason),
        }
        consolidated_item["rationale"] = _build_rationale(
            source=primary_source,
            primary_reason=primary_reason,
            reasons=reasons,
            preview=item.get("preview"),
            tags=tags,
            normalized_path=normalized_path,
            paths=consolidated_item["paths"],
        )
        consolidated.append(consolidated_item)

    return consolidated


def _sort_key(item: dict[str, Any], sort_by: str = "score") -> tuple[Any, ...]:
    score = _coerce_score(item.get("score", 0))
    severity_rank = SEVERITY_RANK.get(str(item.get("severity", "INFO")), 0)
    source_priority = SOURCE_PRIORITY.get(str(item.get("source", "unknown")), 0)
    tags = set(_ensure_list_of_strings(item.get("tags")))
    path_value = str(item.get("normalized_path") or item.get("path", "")).lower()
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
    for item in findings:
        source = str(item.get("source", "unknown")).upper().replace("-", "_")
        finding_key = str(item.get("finding_key", "000000000000")).upper()
        item["finding_id"] = f"TX-{source}-{finding_key[:8]}"


def _build_limitations(
    selected_sources: list[str],
    module_status: list[dict[str, Any]],
    filters: dict[str, Any],
    scope_context,
    *,
    display_truncated: bool,
) -> list[dict[str, Any]]:
    limitations: list[dict[str, Any]] = []
    errored_modules = [entry for entry in module_status if not entry.get("ok")]
    for entry in module_status:
        for limitation in entry.get("limitations", []):
            limitations.append(
                {
                    **limitation,
                    "module": entry["source"],
                }
            )
    if errored_modules:
        limitations.append(
            {
                "type": "partial_coverage",
                "code": "module_errors",
                "message": "One or more analyzer modules failed; absence of findings does not imply full coverage.",
                "modules": [entry["source"] for entry in errored_modules],
            }
        )

    filter_keys = {"severity", "path_contains", "only_writable", "only_existing", "scope"}
    active_filters = {
        key: value
        for key, value in filters.items()
        if key in filter_keys and value not in (None, False, [], ())
    }
    if active_filters:
        limitations.append(
            {
                "type": "filtered_view",
                "code": "results_filtered",
                "message": "User-supplied filters reduced the final finding set.",
                "filters": active_filters,
            }
        )
    if display_truncated:
        limitations.append(
            {
                "type": "display",
                "code": "terminal_truncation",
                "message": "Terminal display was truncated by the configured top-N limit; the saved analysis artifact contains the full filtered result set.",
                "display_limit": int(filters.get("top", 0) or 0),
            }
        )

    limitations.append(
        {
            "type": "scope",
            "code": "module_selection",
            "message": "Only the selected analyzer modules were executed.",
            "modules": selected_sources,
        }
    )
    limitations.append(
        {
            "type": "scope",
            "code": "target_root",
            "message": (
                f"Analysis targeted mounted root {scope_context.root_prefix}."
                if scope_context.root_prefix
                else "Analysis targeted the live host root."
            ),
            "root_prefix": str(scope_context.root_prefix) if scope_context.root_prefix else None,
            "target_root": scope_context.root_label,
        }
    )
    limitations.append(
        {
            "type": "scope",
            "code": "user_enumeration",
            "message": (
                f"User-scoped modules enumerated {len(scope_context.target_users)} local user home paths."
            ),
            "users": [user.username for user in scope_context.target_users],
            "homes": [user.home for user in scope_context.target_users],
        }
    )
    limitations.append(
        {
            "type": "permissions",
            "code": "access_boundaries",
            "message": "Unreadable target paths may reduce observable findings; only accessible artifacts can be analyzed.",
        }
    )
    return limitations


def _build_summary(
    raw_findings: list[dict[str, Any]],
    consolidated_findings: list[dict[str, Any]],
    filtered_findings: list[dict[str, Any]],
    displayed_findings: list[dict[str, Any]],
    module_status: list[dict[str, Any]],
    started_at: float,
) -> dict[str, Any]:
    elapsed_ms = round((perf_counter() - started_at) * 1000, 2)

    severity_counter = Counter(str(item.get("severity", "INFO")).upper() for item in filtered_findings)
    source_counter = Counter(str(item.get("source", "unknown")) for item in filtered_findings)

    tag_counter: Counter[str] = Counter()
    for item in filtered_findings:
        for tag in _ensure_list_of_strings(item.get("tags")):
            tag_counter[tag] += 1

    unique_paths = {
        str(item.get("normalized_path") or item.get("path"))
        for item in filtered_findings
        if item.get("normalized_path") or item.get("path")
    }

    errored_modules = [entry for entry in module_status if not entry.get("ok")]
    module_success_count = len([entry for entry in module_status if entry.get("ok")])

    return {
        "module_success_count": module_success_count,
        "module_count": len(module_status),
        "module_error_count": len(errored_modules),
        "errored_modules": errored_modules,
        "raw_finding_count": len(raw_findings),
        "consolidated_finding_count": len(consolidated_findings),
        "filtered_finding_count": len(filtered_findings),
        "displayed_finding_count": len(displayed_findings),
        "saved_finding_count": len(filtered_findings),
        "display_truncated": len(displayed_findings) < len(filtered_findings),
        "deduplicated_count": max(len(raw_findings) - len(consolidated_findings), 0),
        "unique_path_count": len(unique_paths),
        "analysis_duration_ms": elapsed_ms,
        "severity_counts": {
            sev: severity_counter.get(sev, 0)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        },
        "source_counts": dict(source_counter.most_common(8)),
        "top_tags": dict(tag_counter.most_common(10)),
    }


def _matches_source_filter(item: dict[str, Any], allowed_sources: set[str] | None) -> bool:
    if not allowed_sources:
        return True
    item_sources = {source.strip().lower() for source in _ensure_list_of_strings(item.get("sources") or item.get("source"))}
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
    path_value = item.get("host_path") or item.get("normalized_path") or item.get("path")
    if not path_value:
        return False
    try:
        return Path(str(path_value)).expanduser().exists()
    except OSError:
        return False


def _matches_scope_filter(item: dict[str, Any], scope: str | None) -> bool:
    if not scope:
        return True
    item_scope = str(item.get("scope", "unknown")).lower()
    if scope == "user":
        return item_scope in {"user", "mixed"}
    if scope == "system":
        return item_scope in {"system", "mixed"}
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
    root_prefix: Path | None = None,
) -> dict[str, Any]:
    started_at = perf_counter()
    top = max(int(top), 0)
    selected_sources = sources or list(ANALYZE_SOURCES.keys())
    scope_context = build_scan_scope(root_prefix)

    raw_findings: list[dict[str, Any]] = []
    module_status: list[dict[str, Any]] = []

    with apply_module_scope(selected_sources, scope_context):
        for source in selected_sources:
            analyzer = ANALYZE_SOURCES.get(source)
            if analyzer is None:
                module_status.append(
                    {
                        "source": source,
                        "status": "error",
                        "ok": False,
                        "duration_ms": 0.0,
                        "finding_count": 0,
                        "error": "unknown source",
                        "module_metadata": {},
                    }
                )
                continue

            module = BUILTIN_MODULES.get(source)
            module_metadata = (
                {
                    "display_name": module.metadata.display_name,
                    "analyze_contract": module.metadata.analyze_contract,
                    "heuristic_default": module.metadata.heuristic_profile.default_mode,
                    "scoring_profile": module.metadata.scoring_profile.name,
                }
                if module
                else {}
            )
            results, status = _safe_invoke_module(source, analyzer, module_metadata=module_metadata)
            module_status.append(status)
            if verbose:
                _print_verbose_status(status)

            for item in results:
                if not isinstance(item, dict):
                    continue
                raw_findings.append(_enrich_result(source, item, scope_context=scope_context))

    consolidated_findings = _merge_findings(raw_findings)
    filtered_findings = _apply_filters(
        consolidated_findings,
        severity=severity,
        sources=sources,
        path_contains=path_contains,
        only_writable=only_writable,
        only_existing=only_existing,
        scope=scope,
    )

    reverse_sort = sort_by in {"score", "severity"}
    sorted_findings = sorted(filtered_findings, key=lambda item: _sort_key(item, sort_by=sort_by), reverse=reverse_sort)
    _assign_finding_ids(sorted_findings)
    displayed_findings = sorted_findings[:top]

    summary = _build_summary(
        raw_findings=raw_findings,
        consolidated_findings=consolidated_findings,
        filtered_findings=sorted_findings,
        displayed_findings=displayed_findings,
        module_status=module_status,
        started_at=started_at,
    )

    applied_filters = {
        "severity": severity.lower() if severity else None,
        "sources": sources or [],
        "path_contains": path_contains,
        "only_writable": only_writable,
        "only_existing": only_existing,
        "scope": scope,
        "sort": sort_by,
        "top": top,
    }
    limitations = _build_limitations(
        selected_sources,
        module_status,
        applied_filters,
        scope_context,
        display_truncated=summary["display_truncated"],
    )

    metadata = {
        "schema_version": FINDING_SCHEMA_VERSION,
        "summary": summary,
        "filters": applied_filters,
        "selected_sources": selected_sources,
        "module_status": module_status,
        "module_catalog": {
            name: {
                "display_name": module.metadata.display_name,
                "description": module.metadata.description,
                "analyze_contract": module.metadata.analyze_contract,
                "collect_contract": module.metadata.collect_contract,
                "analysis_behavior": module.metadata.analysis_behavior,
                "collection_behavior": module.metadata.collection_behavior,
                "heuristic_profile": {
                    "default_mode": module.metadata.heuristic_profile.default_mode,
                    "supported_modes": list(module.metadata.heuristic_profile.supported_modes),
                },
                "scoring_profile": {
                    "name": module.metadata.scoring_profile.name,
                    "module_score_delta": module.metadata.scoring_profile.module_score_delta,
                    "environment_score_deltas": module.metadata.scoring_profile.environment_score_deltas,
                },
                "scopes": list(module.metadata.scopes),
                "tags": list(module.metadata.tags),
            }
            for name, module in BUILTIN_MODULES.items()
            if name in selected_sources
        },
        "limitations": limitations,
        "quiet": quiet,
        "scope": {
            "root_prefix": str(scope_context.root_prefix) if scope_context.root_prefix else None,
            "target_root": scope_context.root_label,
            "all_users": [user.username for user in scope_context.target_users],
            "user_homes": [user.home for user in scope_context.target_users],
        },
    }

    output_results(
        mode="analyze",
        results=sorted_findings,
        output_format=output_format,
        output_path=output_path,
        metadata=metadata,
        display_results=displayed_findings,
    )

    return {
        "results": displayed_findings,
        "summary": summary,
        "metadata": metadata,
        "all_results": sorted_findings,
    }


def _print_verbose_status(status: dict[str, Any]) -> None:
    source = status.get("source", "unknown")
    duration_ms = status.get("duration_ms", 0.0)
    finding_count = status.get("finding_count", 0)
    if status.get("ok"):
        print(
            f"[verbose] analyze module={source} status=ok duration_ms={duration_ms} findings={finding_count}"
        )
        return

    error_text = status.get("error", "unknown error")
    print(
        f"[verbose] analyze module={source} status=error duration_ms={duration_ms} findings={finding_count} error={error_text}"
    )
