from __future__ import annotations

import json
import tarfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tenax.collector import ArtifactRecord


def write_collection_outputs(
    *,
    root_output_dir: Path,
    manifest: dict[str, Any],
    artifacts: list[ArtifactRecord],
    references: list[dict[str, Any]],
    errors: list[dict[str, Any]],
    collection_id: str,
    mode: str,
    host: str,
    user: str,
    baseline_name: str | None,
    summary: dict[str, Any],
    location_inventory: dict[str, list[str]],
    limitations: list[dict[str, Any]],
    archive: bool,
) -> Path | None:
    _write_json(root_output_dir / "manifest.json", manifest)
    _write_json(root_output_dir / "artifacts.json", [artifact for artifact in manifest["artifacts"]])
    _write_json(root_output_dir / "references.json", references)
    _write_json(root_output_dir / "errors.json", errors)
    _write_hashes(root_output_dir / "hashes.txt", artifacts)
    _write_summary(
        root_output_dir / "summary.txt",
        collection_id,
        mode,
        host,
        user,
        baseline_name,
        summary,
        artifacts,
        location_inventory,
        limitations,
    )

    if not archive:
        return None

    archive_path = root_output_dir.parent / f"{collection_id}.tgz"
    _archive_directory(root_output_dir, archive_path)
    return archive_path


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def _write_hashes(path: Path, artifacts: list[ArtifactRecord]) -> None:
    lines: list[str] = []
    for artifact in artifacts:
        if artifact.sha256:
            lines.append(f"{artifact.sha256}  {artifact.normalized_path}")
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_summary(
    path: Path,
    collection_id: str,
    mode: str,
    host: str,
    user: str,
    baseline_name: str | None,
    summary: dict[str, Any],
    artifacts: list[ArtifactRecord],
    location_inventory: dict[str, list[str]],
    limitations: list[dict[str, Any]],
) -> None:
    lines: list[str] = []
    lines.append("=== TENAX COLLECT SUMMARY ===")
    lines.append("")
    lines.append(f"Collection ID: {collection_id}")
    lines.append(f"Mode: {mode}")
    lines.append(f"Host: {host}")
    lines.append(f"User: {user}")
    lines.append(f"Target Root: {next((item['target_root'] for item in limitations if item.get('code') == 'target_root'), 'unknown')}")
    if baseline_name:
        lines.append(f"Baseline Name: {baseline_name}")
    lines.append("")
    lines.append("--- Totals ---")
    lines.append(f"Artifacts collected: {summary['artifact_count']}")
    lines.append(f"Direct artifacts: {summary['direct_artifact_count']}")
    lines.append(f"Reference artifacts: {summary['reference_artifact_count']}")
    lines.append(f"References found: {summary['reference_count']}")
    lines.append(f"Required references followed: {summary['followed_required_reference_count']} of {summary['required_reference_count']}")
    lines.append(f"Artifacts copied: {summary['copied_artifact_count']}")
    lines.append(f"Errors: {summary['error_count']}")
    lines.append("")
    if limitations:
        lines.append("--- Limitations ---")
        for limitation in limitations:
            lines.append(f"- {limitation.get('message', 'Unknown limitation')}")
        lines.append("")
    lines.append("--- By Module ---")
    for module_name, count in sorted(summary["module_counts"].items()):
        lines.append(f"{module_name}: {count}")
    lines.append("")
    lines.append("--- Watched Locations Inventory ---")
    for module, tree_lines in location_inventory.items():
        lines.append(f"[{module}]")
        for line in tree_lines:
            lines.append(line)
        lines.append("")
    lines.append("--- Collected Artifacts ---")
    for artifact in artifacts:
        lines.append(f"[{artifact.id}] {artifact.module} | {artifact.artifact_type}")
        lines.append(f"Path: {artifact.path}")
        if artifact.host_path and artifact.host_path != artifact.path:
            lines.append(f"Host Path: {artifact.host_path}")
        lines.append(f"Discovery: {artifact.discovery_mode}")
        lines.append(f"Collection Mode: {artifact.collection_mode}")
        if artifact.discovered_from:
            lines.append(f"Discovered From: {artifact.discovered_from}")
        if artifact.reference_reason:
            lines.append(f"Reference Reason: {artifact.reference_reason}")
        if artifact.rationale.get("why_collected"):
            lines.append(f"Why Collected: {'; '.join(artifact.rationale['why_collected'])}")
        if artifact.sha256:
            lines.append(f"SHA256: {artifact.sha256}")
        if artifact.preview:
            lines.append(f"Preview: {artifact.preview[:400]}")
        if artifact.limitations:
            lines.append(f"Limitations: {'; '.join(artifact.limitations)}")
        if artifact.copy_status.copied and artifact.copy_status.copied_to:
            lines.append(f"Copied To: {artifact.copy_status.copied_to}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def _archive_directory(source_dir: Path, archive_path: Path) -> None:
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(source_dir, arcname=source_dir.name)
