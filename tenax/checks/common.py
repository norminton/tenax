from __future__ import annotations

import pwd
from pathlib import Path
from typing import Any

from tenax.utils import build_collect_record as _build_collect_record


def build_collect_record(path: Path, hash_files: bool = False) -> dict[str, Any]:
    return _build_collect_record(path, hash_files=hash_files)


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


def finalize_finding(
    path: Path,
    hits: dict[str, dict[str, Any]],
    *,
    high_confidence_categories: set[str],
    low_signal_only_categories: set[str] | None = None,
    minimum_score_without_high_confidence: int = 95,
    minimum_categories_without_high_confidence: int = 2,
    mode: str = "strict",
) -> dict[str, Any] | None:
    if not hits:
        return None

    reasons = [entry["reason"] for entry in hits.values()]
    previews = [entry["preview"] for entry in hits.values() if entry.get("preview")]
    categories = {entry["category"] for entry in hits.values()}
    score = sum(int(entry["score"]) for entry in hits.values())

    if mode == "strict":
        low_signal_only_categories = low_signal_only_categories or set()
        has_high_confidence = bool(categories & high_confidence_categories)
        only_low_signal = categories and categories.issubset(low_signal_only_categories)

        if only_low_signal and score < 90:
            return None

        if (
            not has_high_confidence
            and score < minimum_score_without_high_confidence
            and len(categories) < minimum_categories_without_high_confidence
        ):
            return None

    primary_reason = max(
        hits.values(),
        key=lambda entry: int(entry["score"]),
    )["reason"]

    preview = previews[0] if previews else None

    return {
        "path": str(path),
        "score": score,
        "severity": severity_from_score(score),
        "reason": primary_reason,
        "reasons": reasons,
        "preview": preview,
    }
