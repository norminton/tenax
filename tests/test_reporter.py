from __future__ import annotations

import json
from pathlib import Path

from tenax import output_paths
from tenax import reporter


def test_output_results_writes_full_analyze_artifact_to_project_output_and_keeps_terminal_slice(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    repo_root = tmp_path / "repo"
    (repo_root / "tenax").mkdir(parents=True)
    (repo_root / "pyproject.toml").write_text("[project]\nname='tenax'\n", encoding="utf-8")
    (repo_root / "README.md").write_text("# Tenax\n", encoding="utf-8")
    monkeypatch.chdir(repo_root)

    full_results = [
        {"finding_id": "TX-1", "severity": "CRITICAL", "source": "systemd", "path": "/tmp/one", "score": 100},
        {"finding_id": "TX-2", "severity": "HIGH", "source": "systemd", "path": "/tmp/two", "score": 90},
        {"finding_id": "TX-3", "severity": "MEDIUM", "source": "systemd", "path": "/tmp/three", "score": 60},
    ]
    display_results = full_results[:1]
    metadata = {
        "summary": {
            "filtered_finding_count": 3,
            "saved_finding_count": 3,
            "displayed_finding_count": 1,
            "display_truncated": True,
            "module_success_count": 1,
            "module_count": 1,
            "module_error_count": 0,
        },
        "limitations": [],
    }

    reporter.output_results(
        mode="analyze",
        results=full_results,
        output_format="json",
        metadata=metadata,
        display_results=display_results,
    )

    saved_files = sorted((repo_root / "output").glob("analyze_*.json"))
    assert len(saved_files) == 1

    saved_payload = json.loads(saved_files[0].read_text(encoding="utf-8"))
    assert saved_payload["count"] == 3
    assert len(saved_payload["results"]) == 3
    assert saved_payload["metadata"]["summary"]["saved_finding_count"] == 3
    assert saved_payload["metadata"]["summary"]["displayed_finding_count"] == 1

    terminal = capsys.readouterr().out
    assert '"count": 1' in terminal
    assert 'Saved full analyze output to:' in terminal


def test_output_results_recovers_project_output_dir_from_virtualenv_site_packages(
    monkeypatch,
    tmp_path: Path,
) -> None:
    repo_root = tmp_path / "tenax"
    (repo_root / "tenax").mkdir(parents=True)
    (repo_root / "pyproject.toml").write_text("[project]\nname='tenax'\n", encoding="utf-8")
    (repo_root / "README.md").write_text("# Tenax\n", encoding="utf-8")

    fake_reporter = repo_root / ".venv" / "lib" / "python3.12" / "site-packages" / "tenax" / "reporter.py"
    fake_reporter.parent.mkdir(parents=True)
    fake_reporter.write_text("# reporter stub\n", encoding="utf-8")

    monkeypatch.setattr(output_paths, "__file__", str(fake_reporter))
    monkeypatch.setattr(output_paths.sys, "prefix", str(repo_root / ".venv"))
    monkeypatch.chdir(tmp_path)

    reporter.output_results(
        mode="analyze",
        results=[{"finding_id": "TX-1", "severity": "CRITICAL", "source": "systemd", "path": "/tmp/one", "score": 100}],
        output_format="json",
        metadata={"summary": {"filtered_finding_count": 1, "displayed_finding_count": 1, "saved_finding_count": 1}},
    )

    saved_files = sorted((repo_root / "output").glob("analyze_*.json"))
    assert len(saved_files) == 1


def test_resolve_runtime_output_dir_falls_back_to_working_tree_not_site_packages(
    monkeypatch,
    tmp_path: Path,
) -> None:
    fake_site_packages = tmp_path / "venv" / "lib" / "python3.12" / "site-packages" / "tenax" / "output_paths.py"
    fake_site_packages.parent.mkdir(parents=True)
    fake_site_packages.write_text("# output paths stub\n", encoding="utf-8")

    monkeypatch.setattr(output_paths, "__file__", str(fake_site_packages))
    monkeypatch.setattr(output_paths.sys, "prefix", str(tmp_path / "venv"))
    monkeypatch.chdir(tmp_path)

    output_dir = output_paths.resolve_runtime_output_dir()

    assert output_dir == tmp_path / "output"
