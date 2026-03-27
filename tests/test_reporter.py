from __future__ import annotations

import json
from pathlib import Path

from tenax import reporter


def test_output_results_writes_full_analyze_artifact_to_outputs_and_keeps_terminal_slice(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    fake_reporter = tmp_path / "repo" / "tenax" / "reporter.py"
    fake_reporter.parent.mkdir(parents=True)
    fake_reporter.write_text("# reporter stub\n", encoding="utf-8")
    monkeypatch.setattr(reporter, "__file__", str(fake_reporter))

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

    saved_files = sorted((tmp_path / "repo" / "outputs").glob("analyze_*.json"))
    assert len(saved_files) == 1

    saved_payload = json.loads(saved_files[0].read_text(encoding="utf-8"))
    assert saved_payload["count"] == 3
    assert len(saved_payload["results"]) == 3
    assert saved_payload["metadata"]["summary"]["saved_finding_count"] == 3
    assert saved_payload["metadata"]["summary"]["displayed_finding_count"] == 1

    terminal = capsys.readouterr().out
    assert '"count": 1' in terminal
    assert 'Saved full analyze output to:' in terminal
