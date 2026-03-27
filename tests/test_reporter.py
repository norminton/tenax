from __future__ import annotations

import json
from pathlib import Path

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
