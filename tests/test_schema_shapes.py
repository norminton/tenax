from __future__ import annotations

import json
from pathlib import Path

import pytest

from tenax import analyzer, reporter

from .conftest import assert_analyze_finding_shape


def test_reporter_json_output_preserves_findings_and_metadata_shape(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    out_dir = tmp_path / "output"
    monkeypatch.setattr(reporter, "_get_tenax_output_dir", lambda: out_dir)
    results = [
        {
            "finding_id": "TX-SSH-ABC12345",
            "schema_version": "1.1",
            "rule_id": "TX-RULE-SSH-SSH_PERSISTENCE",
            "rule_name": "ssh suspicious persistence artifact",
            "source_module": "ssh",
            "source": "ssh",
            "score": 95,
            "severity": "CRITICAL",
            "reason": "SSH artifact executes content from a temporary path",
            "rationale": {
                "summary": "SSH artifact executes content from a temporary path",
                "source": "ssh",
                "reasons": ["SSH artifact executes content from a temporary path"],
                "evidence_preview": "command=/tmp/dropper",
                "tags": ["ssh", "writable"],
                "primary_path": "/tmp/authorized_keys",
                "paths": ["/tmp/authorized_keys"],
            },
            "tags": ["ssh", "writable"],
            "scope": "user",
            "paths": ["/tmp/authorized_keys"],
            "evidence": {"preview": "command=/tmp/dropper", "reasons": ["reason"], "paths": ["/tmp/authorized_keys"]},
            "dedupe": {"merged_count": 1, "sources": ["ssh"], "rule_ids": ["TX-RULE-SSH-SSH_PERSISTENCE"]},
            "finding_key": "abc123",
            "path": "/tmp/authorized_keys",
        }
    ]
    metadata = {
        "schema_version": "1.1",
        "summary": {"filtered_finding_count": 1, "displayed_finding_count": 1, "module_success_count": 1, "module_count": 1},
        "filters": {"severity": "high"},
        "selected_sources": ["ssh"],
        "module_status": [{"source": "ssh", "ok": True}],
        "limitations": [{"code": "module_selection", "message": "Only selected modules ran."}],
    }

    reporter.output_results(
        mode="analyze",
        results=results,
        output_format="json",
        output_path=None,
        metadata=metadata,
    )

    saved = sorted(out_dir.glob("analyze_*.json"))
    assert saved
    payload = json.loads(saved[-1].read_text(encoding="utf-8"))

    assert payload["mode"] == "analyze"
    assert payload["count"] == 1
    assert payload["metadata"]["schema_version"] == "1.1"
    assert payload["metadata"]["filters"]["severity"] == "high"
    assert payload["metadata"]["limitations"][0]["code"] == "module_selection"
    assert_analyze_finding_shape(payload["results"][0])


def test_run_analysis_assigns_stable_required_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        analyzer,
        "ANALYZE_SOURCES",
        {
            "sudoers": lambda: [
                {
                    "path": "/tmp/sudoers",
                    "score": 100,
                    "reason": "sudoers grants NOPASSWD: ALL",
                    "preview": "ALL=(ALL) NOPASSWD: ALL",
                }
            ]
        },
    )
    monkeypatch.setattr(analyzer, "output_results", lambda **kwargs: None)

    payload = analyzer.run_analysis(output_format="json", sources=["sudoers"])

    assert payload["results"]
    finding = payload["results"][0]
    assert_analyze_finding_shape(finding)
    assert finding["finding_id"].startswith("TX-SUDOERS-")
    assert finding["rule_id"].startswith("TX-RULE-SUDOERS-")
    assert finding["source_module"] == "sudoers"
    assert finding["evidence"]["paths"] == ["/tmp/sudoers"]
    assert finding["rationale"]["summary"] == "sudoers grants NOPASSWD: ALL"


def test_render_text_formats_preview_as_wrapped_block() -> None:
    rendered = reporter.render_text(
        "analyze",
        [
            {
                "finding_id": "TX-SYSTEMD-ABC12345",
                "severity": "HIGH",
                "source": "systemd",
                "path": "/etc/systemd/system/demo.service",
                "score": 95,
                "rule_id": "TX-RULE-SYSTEMD-TEMP_PATH",
                "reason": "Systemd unit executes from a temporary path",
                "preview": "line 12: ExecStart=/tmp/.cache/dbus-update --daemon --with-a-very-long-argument-string-for-wrapping",
            }
        ],
        metadata={},
    )

    assert "  preview:" in rendered
    assert "    line 12: ExecStart=/tmp/.cache/dbus-update" in rendered
