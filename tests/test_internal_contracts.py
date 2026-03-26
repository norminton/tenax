from __future__ import annotations

from pathlib import Path
import tomllib

from tenax import analyzer, collector
from tenax.checks import BUILTIN_MODULES
from tenax.checks.common import finalize_finding, record_hit
from tenax.utils import build_collect_record


def test_builtin_module_registry_exposes_standardized_contracts() -> None:
    assert "systemd" in BUILTIN_MODULES
    module = BUILTIN_MODULES["systemd"]

    assert module.metadata.analyze_contract == "list[finding]"
    assert module.metadata.collect_contract == "list[artifact]"
    assert module.metadata.heuristic_profile.default_mode == "strict"
    assert "expanded" in module.metadata.heuristic_profile.supported_modes
    assert module.metadata.scoring_profile.name == "default"


def test_analyzer_metadata_exposes_module_catalog(monkeypatch) -> None:
    monkeypatch.setattr(
        analyzer,
        "ANALYZE_SOURCES",
        {"systemd": lambda: [{"path": "/tmp/demo.service", "score": 91, "reason": "bad unit"}]},
    )
    monkeypatch.setattr(analyzer, "output_results", lambda **kwargs: None)

    payload = analyzer.run_analysis(output_format="json", sources=["systemd"])

    module_catalog = payload["metadata"]["module_catalog"]
    assert module_catalog["systemd"]["analyze_contract"] == "list[finding]"
    assert module_catalog["systemd"]["collect_contract"] == "list[artifact]"
    assert module_catalog["systemd"]["heuristic_profile"]["default_mode"] == "strict"
    assert module_catalog["systemd"]["scoring_profile"]["name"] == "default"


def test_collector_manifest_exposes_module_catalog(tmp_path: Path, monkeypatch) -> None:
    artifact = tmp_path / "demo.service"
    artifact.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
    monkeypatch.setattr(
        collector,
        "CHECK_REGISTRY",
        {"systemd": lambda **kwargs: [{"path": str(artifact)}]},
    )

    collector.run_collection(
        output_path=tmp_path / "out",
        modules=["systemd"],
        mode="structured",
        hash_files=False,
        follow_references=False,
    )

    run_dir = sorted((tmp_path / "out").glob("collect_*"))[-1]
    manifest = (run_dir / "manifest.json").read_text(encoding="utf-8")

    assert '"module_catalog"' in manifest
    assert '"analyze_contract": "list[finding]"' in manifest
    assert '"collect_contract": "list[artifact]"' in manifest


def test_shared_finalize_finding_supports_strict_and_expanded_modes() -> None:
    strict_hits: dict[str, dict[str, object]] = {}
    record_hit(strict_hits, "low signal", 25, "preview", "low")

    assert finalize_finding(
        Path("/tmp/demo"),
        strict_hits,
        high_confidence_categories={"high"},
        low_signal_only_categories={"low"},
        mode="strict",
    ) is None

    expanded = finalize_finding(
        Path("/tmp/demo"),
        strict_hits,
        high_confidence_categories={"high"},
        low_signal_only_categories={"low"},
        mode="expanded",
    )
    assert expanded is not None
    assert expanded["severity"] == "LOW"


def test_shared_collect_record_shapes_metadata(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("hello\n", encoding="utf-8")

    record = build_collect_record(artifact, hash_files=True)

    assert record["path"] == str(artifact)
    assert record["exists"] is True
    assert record["permissions"].startswith("0o")
    assert "sha256" in record


def test_repository_root_packaging_exposes_tenax_console_script() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    pyproject_path = repo_root / "pyproject.toml"

    assert pyproject_path.exists()

    pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    assert pyproject["project"]["name"] == "tenax"
    assert pyproject["project"]["scripts"]["tenax"] == "tenax.cli:main"
