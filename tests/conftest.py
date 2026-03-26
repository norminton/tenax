from __future__ import annotations

import shutil
from pathlib import Path

import pytest


FIXTURES_ROOT = Path(__file__).parent / "fixtures"
SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def fixture_path(*parts: str) -> Path:
    return FIXTURES_ROOT.joinpath(*parts)


@pytest.fixture
def fixture_file_factory(tmp_path: Path):
    def factory(*parts: str, mode: int | None = None, target_name: str | None = None) -> Path:
        source = fixture_path(*parts)
        if not source.is_file():
            raise FileNotFoundError(source)

        destination_name = target_name or source.name
        destination = tmp_path / destination_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        if mode is not None:
            destination.chmod(mode)
        return destination

    return factory


def assert_basic_module_finding(finding: dict[str, object], expected_path: Path) -> None:
    assert finding["path"] == str(expected_path)
    assert isinstance(finding["score"], int)
    assert finding["score"] > 0
    assert finding["severity"] in SEVERITIES
    assert isinstance(finding["reason"], str)
    assert finding["reason"]
    assert isinstance(finding["reasons"], list)
    assert finding["reasons"]
    if finding.get("preview") is not None:
        assert isinstance(finding["preview"], str)


def assert_analyze_finding_shape(finding: dict[str, object]) -> None:
    required_keys = {
        "finding_id",
        "schema_version",
        "rule_id",
        "rule_name",
        "source_module",
        "score",
        "severity",
        "reason",
        "rationale",
        "tags",
        "scope",
        "paths",
        "evidence",
        "dedupe",
        "finding_key",
    }
    assert required_keys.issubset(finding.keys())
    assert finding["schema_version"] == "1.1"
    assert finding["severity"] in SEVERITIES
    assert isinstance(finding["tags"], list)
    assert isinstance(finding["paths"], list)
    assert isinstance(finding["rationale"], dict)
    assert isinstance(finding["evidence"], dict)
    assert isinstance(finding["dedupe"], dict)


def assert_manifest_artifact_shape(artifact: dict[str, object]) -> None:
    required_keys = {
        "id",
        "module",
        "collection_mode",
        "artifact_type",
        "path",
        "normalized_path",
        "discovery_mode",
        "exists",
        "is_file",
        "is_dir",
        "is_symlink",
        "content_capture",
        "parsed",
        "evidence",
        "rationale",
        "lineage",
        "limitations",
        "references",
        "copy_status",
        "module_metadata",
        "errors",
    }
    assert required_keys.issubset(artifact.keys())
    assert isinstance(artifact["content_capture"], dict)
    assert isinstance(artifact["parsed"], dict)
    assert isinstance(artifact["evidence"], dict)
    assert isinstance(artifact["rationale"], dict)
    assert isinstance(artifact["lineage"], dict)
    assert isinstance(artifact["limitations"], list)
    assert isinstance(artifact["references"], list)
    assert isinstance(artifact["copy_status"], dict)
    assert isinstance(artifact["module_metadata"], dict)
    assert isinstance(artifact["errors"], list)


def assert_reference_shape(reference: dict[str, object]) -> None:
    required_keys = {
        "id",
        "ref_type",
        "value",
        "reason",
        "parent_path",
        "parent_module",
        "depth",
        "classification",
        "collection_required",
        "followed",
        "copied",
        "errors",
    }
    assert required_keys.issubset(reference.keys())
    assert reference["ref_type"] in {"path", "url"}
    assert isinstance(reference["errors"], list)
