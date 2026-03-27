from __future__ import annotations

import hashlib
import pwd
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


def _select_investigator_preview(hits: dict[str, dict[str, Any]]) -> str | None:
    best_preview: str | None = None
    best_rank: tuple[int, int, int] | None = None

    for entry in hits.values():
        preview = entry.get("preview")
        if not preview:
            continue

        preview_text = str(preview)
        score = int(entry.get("score", 0))
        category = str(entry.get("category", ""))
        rank = (
            1 if preview_text.lower().startswith("line ") else 0,
            0 if category in {"ownership", "permissions"} else 1,
            score,
        )

        if best_rank is None or rank > best_rank:
            best_rank = rank
            best_preview = preview_text

    return best_preview


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

    preview = _select_investigator_preview(hits)

    return {
        "path": str(path),
        "score": score,
        "severity": severity_from_score(score),
        "reason": primary_reason,
        "reasons": reasons,
        "preview": preview,
    }
