from __future__ import annotations

import hashlib
import pwd
import re
from pathlib import Path
from typing import Any

from tenax.utils import build_collect_record as _build_collect_record


def build_collect_record(path: Path, hash_files: bool = False) -> dict[str, Any]:
    return _build_collect_record(path, hash_files=hash_files)


def build_collect_record_with_metadata(
    path: Path,
    *,
    hash_files: bool = False,
    extra_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record = build_collect_record(path, hash_files=hash_files)
    if extra_fields:
        record.update(extra_fields)
    return record


def safe_iterdir(path: Path) -> list[Path]:
    try:
        return list(path.iterdir())
    except Exception:
        return []


def safe_walk(base: Path) -> list[Path]:
    output: list[Path] = []
    try:
        for child in base.rglob("*"):
            if child.is_file() or child.is_symlink():
                output.append(child)
    except Exception:
        return output
    return output


def safe_stat(path: Path):
    try:
        return path.stat()
    except Exception:
        return None


def safe_lstat(path: Path):
    try:
        return path.lstat()
    except Exception:
        return None


def owner_from_uid(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def path_startswith_any(path_value: str, prefixes: tuple[str, ...]) -> bool:
    path_lower = path_value.lower()
    return any(path_lower.startswith(prefix.lower()) for prefix in prefixes)


def contains_high_risk_path(line_lower: str, *, temp_path_patterns: tuple[str, ...], user_path_regex) -> bool:
    if any(token in line_lower for token in temp_path_patterns):
        return True
    return bool(user_path_regex.search(line_lower))


def with_line_number(line_number: int, line: str) -> str:
    return f"line {line_number}: {line.strip()}"


def with_line_number_clamped(line_number: int, line: str, *, max_length: int = 220) -> str:
    flattened = " ".join(line.split())
    if len(flattened) > max_length:
        flattened = flattened[: max_length - 3] + "..."
    return f"L{line_number}: {flattened}"


LINE_PREFIX_REGEX = re.compile(r"^(line \d+:|L\d+:)\s*", re.IGNORECASE)
METADATA_ONLY_PREFIXES = ("owner=", "mode=")
PLACEHOLDER_PREVIEWS = {"[binary content omitted]"}
BEHAVIORAL_PREVIEW_TOKENS = (
    "execstart=",
    "exec=",
    "command=",
    "authorizedkeyscommand",
    "ld_preload",
    "ld_library_path",
    "path=",
    "curl",
    "wget",
    "fetch",
    "bash -c",
    "python -c",
    "perl -e",
    "base64",
    "socket",
    "connect(",
    "nopasswd",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/shm/",
    "/home/",
    "/root/",
)


def normalize_preview_text(preview: str | None) -> str | None:
    if preview is None:
        return None
    flattened = " ".join(str(preview).split()).strip()
    return flattened or None


def preview_rank(
    preview: str | None,
    *,
    score: int = 0,
    category: str | None = None,
) -> tuple[int, int, int, int, int, int]:
    preview_text = normalize_preview_text(preview)
    if not preview_text:
        return (0, 0, 0, 0, 0, 0)

    preview_lower = preview_text.lower()
    category_lower = (category or "").lower()
    is_line_preview = 1 if LINE_PREFIX_REGEX.match(preview_text) else 0
    has_behavioral_text = 1 if any(token in preview_lower for token in BEHAVIORAL_PREVIEW_TOKENS) else 0
    is_placeholder = 1 if preview_lower in PLACEHOLDER_PREVIEWS else 0
    is_metadata_only = 1 if preview_lower.startswith(METADATA_ONLY_PREFIXES) else 0
    category_is_metadata = 1 if category_lower in {"ownership", "permissions"} else 0
    return (
        is_line_preview,
        has_behavioral_text,
        0 if (is_metadata_only or category_is_metadata) else 1,
        0 if is_placeholder else 1,
        score,
        -len(preview_text),
    )


def choose_preferred_preview(
    current_preview: str | None,
    candidate_preview: str | None,
    *,
    current_score: int = 0,
    candidate_score: int = 0,
    current_category: str | None = None,
    candidate_category: str | None = None,
) -> str | None:
    current_text = normalize_preview_text(current_preview)
    candidate_text = normalize_preview_text(candidate_preview)

    if not current_text:
        return candidate_text
    if not candidate_text:
        return current_text

    current_rank = preview_rank(
        current_text,
        score=current_score,
        category=current_category,
    )
    candidate_rank = preview_rank(
        candidate_text,
        score=candidate_score,
        category=candidate_category,
    )
    return candidate_text if candidate_rank > current_rank else current_text


def record_hit(
    hits: dict[str, dict[str, Any]],
    reason: str,
    score: int,
    preview: str | None,
    category: str,
    *,
    heuristic: str = "strict",
) -> None:
    existing = hits.get(category)
    if existing is None or score > int(existing["score"]):
        hits[category] = {
            "reason": reason,
            "score": int(score),
            "preview": preview,
            "category": category,
            "heuristic": heuristic,
        }


def severity_from_score(score: int) -> str:
    if score >= 140:
        return "CRITICAL"
    if score >= 90:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"


def sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return None


def select_investigator_preview(
    hits: dict[str, dict[str, Any]],
    *,
    fallback: str | None = None,
) -> str | None:
    best_preview: str | None = None
    best_rank: tuple[int, int, int, int, int, int] | None = None

    for entry in hits.values():
        preview = entry.get("preview")
        if not preview:
            continue

        preview_text = normalize_preview_text(str(preview))
        if not preview_text:
            continue
        rank = preview_rank(
            preview_text,
            score=int(entry.get("score", 0)),
            category=str(entry.get("category", "")),
        )

        if best_rank is None or rank > best_rank:
            best_rank = rank
            best_preview = preview_text

    if best_preview:
        return best_preview
    return normalize_preview_text(fallback)


def finalize_finding(
    path: Path,
    hits: dict[str, dict[str, Any]],
    *,
    high_confidence_categories: set[str],
    low_signal_only_categories: set[str] | None = None,
    minimum_score_without_high_confidence: int = 95,
    minimum_categories_without_high_confidence: int = 2,
    non_behavioral_categories: set[str] | None = None,
    mode: str = "strict",
) -> dict[str, Any] | None:
    if not hits:
        return None

    reasons = [entry["reason"] for entry in hits.values()]
    categories = {entry["category"] for entry in hits.values()}
    score = sum(int(entry["score"]) for entry in hits.values())
    non_behavioral_categories = non_behavioral_categories or set()

    threshold_entries = [
        entry for entry in hits.values() if entry.get("category") not in non_behavioral_categories
    ]
    threshold_categories = {entry["category"] for entry in threshold_entries}
    threshold_score = sum(int(entry["score"]) for entry in threshold_entries)

    if mode == "strict":
        if not threshold_categories:
            return None

        low_signal_only_categories = low_signal_only_categories or set()
        has_high_confidence = bool(threshold_categories & high_confidence_categories)
        only_low_signal = threshold_categories.issubset(low_signal_only_categories)

        if only_low_signal and threshold_score < 90:
            return None

        if (
            not has_high_confidence
            and threshold_score < minimum_score_without_high_confidence
            and len(threshold_categories) < minimum_categories_without_high_confidence
        ):
            return None

    primary_reason = max(
        hits.values(),
        key=lambda entry: int(entry["score"]),
    )["reason"]

    preview = select_investigator_preview(hits)

    return {
        "path": str(path),
        "score": score,
        "severity": severity_from_score(score),
        "reason": primary_reason,
        "reasons": reasons,
        "preview": preview,
    }
