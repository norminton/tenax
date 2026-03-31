from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tenax import analyzer, cli

from .conftest import assert_analyze_finding_shape


def _finding(
    path: str,
    *,
    score: int,
    severity: str | None = None,
    reason: str = "suspicious persistence artifact",
    preview: str = "",
    tags: list[str] | None = None,
) -> dict[str, object]:
    finding: dict[str, object] = {
        "path": path,
        "score": score,
        "reason": reason,
    }
    if severity is not None:
        finding["severity"] = severity
    if preview:
        finding["preview"] = preview
    if tags:
        finding["tags"] = tags
    return finding


def test_run_analysis_applies_repaired_filters_and_schema(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    writable_user_file = tmp_path / ".bashrc"
    writable_user_file.write_text("echo hi\n", encoding="utf-8")

    system_file = tmp_path / "system.service"
    system_file.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")

    missing_file = tmp_path / "missing.service"

    monkeypatch.setattr(
        analyzer,
        "ANALYZE_SOURCES",
        {
            "systemd": lambda: [
                _finding(
                    str(writable_user_file),
                    score=95,
                    reason="world-writable service override",
                    preview="ExecStart=/tmp/payload",
                    tags=["user-scope", "writable"],
                ),
                _finding(
                    str(writable_user_file),
                    score=80,
                    reason="duplicate lower-score hit",
                ),
                _finding(
                    str(missing_file),
                    score=90,
                    severity="HIGH",
                    reason="missing system artifact",
                    tags=["system-scope", "writable"],
                ),
                _finding(
                    str(system_file),
                    score=60,
                    severity="MEDIUM",
                    reason="system-level service anomaly",
                    tags=["system-scope"],
                ),
            ],
            "ssh": lambda: [
                _finding(
                    str(tmp_path / "authorized_keys"),
                    score=20,
                    severity="LOW",
                    reason="user key",
                    tags=["user-scope"],
                ),
            ],
        },
    )

    captured: dict[str, object] = {}

    def fake_output_results(
        *,
        mode: str,
        results: list[dict[str, object]],
        output_format: str,
        output_path,
        metadata,
        display_results=None,
    ):
        captured["mode"] = mode
        captured["results"] = results
        captured["metadata"] = metadata
        captured["display_results"] = display_results

    monkeypatch.setattr(analyzer, "output_results", fake_output_results)

    payload = analyzer.run_analysis(
        output_format="json",
        severity="MEDIUM",
        sources=["systemd", "ssh"],
        path_contains=str(tmp_path),
        only_writable=True,
        only_existing=True,
        scope="user",
        sort_by="severity",
        top=10,
    )

    assert captured["mode"] == "analyze"
    assert payload["summary"]["filtered_finding_count"] == 1
    assert payload["summary"]["deduplicated_count"] == 1
    assert payload["summary"]["saved_finding_count"] == 1
    assert payload["summary"]["displayed_finding_count"] == 1

    finding = payload["results"][0]
    assert_analyze_finding_shape(finding)
    assert finding["path"] == str(writable_user_file)
    assert finding["source_module"] == "systemd"
    assert finding["severity"] == "CRITICAL"
    assert finding["scope"] == "user"
    assert finding["paths"] == [str(writable_user_file)]
    assert finding["evidence"]["preview"] == "ExecStart=/tmp/payload"
    assert finding["dedupe"]["merged_count"] == 2
    assert "writable" in finding["tags"]
    assert any(item["code"] == "results_filtered" for item in payload["metadata"]["limitations"])
    assert captured["results"] == payload["all_results"]
    assert captured["display_results"] == payload["results"]
    assert payload["metadata"]["filters"]["severity"] == "medium"
    assert payload["metadata"]["filters"]["only_writable"] is True
    assert payload["metadata"]["filters"]["only_existing"] is True
    assert payload["metadata"]["filters"]["scope"] == "user"
    assert payload["metadata"]["filters"]["sort"] == "severity"


def test_run_analysis_honors_sort_semantics_on_live_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        analyzer,
        "ANALYZE_SOURCES",
        {
            "cron": lambda: [
                _finding("/tmp/medium.cron", score=60, severity="MEDIUM", reason="medium hit"),
                _finding("/tmp/high.cron", score=75, severity="HIGH", reason="high hit"),
            ],
            "ssh": lambda: [
                _finding("/tmp/critical.key", score=95, severity="CRITICAL", reason="critical hit"),
            ],
        },
    )
    monkeypatch.setattr(analyzer, "output_results", lambda **kwargs: None)

    severity_sorted = analyzer.run_analysis(
        output_format="json",
        sources=["cron", "ssh"],
        sort_by="severity",
        top=10,
    )["results"]
    assert [item["severity"] for item in severity_sorted] == ["CRITICAL", "HIGH", "MEDIUM"]

    path_sorted = analyzer.run_analysis(
        output_format="json",
        sources=["cron", "ssh"],
        sort_by="path",
        top=10,
    )["results"]
    assert [Path(item["path"]).name for item in path_sorted] == ["critical.key", "high.cron", "medium.cron"]


def test_run_analysis_reports_coverage_and_module_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        analyzer,
        "ANALYZE_SOURCES",
        {
            "systemd": lambda: [_finding("/tmp/demo.service", score=91, reason="bad unit")],
            "cron": lambda: (_ for _ in ()).throw(RuntimeError("boom")),
        },
    )
    monkeypatch.setattr(analyzer, "output_results", lambda **kwargs: None)

    payload = analyzer.run_analysis(
        output_format="json",
        sources=["systemd", "cron", "missing"],
        top=5,
    )

    metadata = payload["metadata"]
    assert metadata["selected_sources"] == ["systemd", "cron", "missing"]
    assert payload["summary"]["module_count"] == 3
    assert payload["summary"]["module_error_count"] == 2
    assert any(item["code"] == "module_errors" for item in metadata["limitations"])
    assert any(item["code"] == "module_selection" for item in metadata["limitations"])

    cron_status = next(item for item in metadata["module_status"] if item["source"] == "cron")
    missing_status = next(item for item in metadata["module_status"] if item["source"] == "missing")
    assert cron_status["ok"] is False
    assert "RuntimeError" in cron_status["error"]
    assert missing_status["ok"] is False
    assert missing_status["error"] == "unknown source"


def test_run_analysis_verbose_prints_module_execution_details(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        analyzer,
        "ANALYZE_SOURCES",
        {
            "systemd": lambda: [_finding("/tmp/demo.service", score=91, reason="bad unit")],
            "cron": lambda: (_ for _ in ()).throw(RuntimeError("boom")),
        },
    )
    monkeypatch.setattr(analyzer, "output_results", lambda **kwargs: None)

    analyzer.run_analysis(
        output_format="json",
        sources=["systemd", "cron"],
        verbose=True,
        top=5,
    )

    output = capsys.readouterr().out
    assert "module=systemd" in output
    assert "findings=1" in output
    assert "module=cron" in output
    assert "status=error" in output
    assert "boom" in output


def test_run_analysis_keeps_distinct_rule_contexts_on_same_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        analyzer,
        "ANALYZE_SOURCES",
        {
            "systemd": lambda: [
                _finding("/tmp/persist.service", score=95, reason="systemd service executes payload from temp path", tags=["service-definition", "temp-path"]),
                _finding("/tmp/persist.service", score=80, reason="systemd service downloads remote payload", tags=["service-definition", "network-retrieval"]),
            ],
        },
    )
    monkeypatch.setattr(analyzer, "output_results", lambda **kwargs: None)

    payload = analyzer.run_analysis(output_format="json", sources=["systemd"], top=10)

    assert payload["summary"]["filtered_finding_count"] == 2
    assert {item["path"] for item in payload["results"]} == {"/tmp/persist.service"}
    assert len({item["rule_id"] for item in payload["results"]}) == 2


def test_run_analysis_reports_missing_getcap_as_limitation_not_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def capability_module() -> list[dict[str, object]]:
        setattr(
            capability_module,
            "_tenax_limitations",
            [
                {
                    "type": "unsupported_dependency",
                    "code": "missing_getcap",
                    "message": "Capability analysis skipped because the 'getcap' command is unavailable.",
                }
            ],
        )
        return []

    monkeypatch.setattr(analyzer, "ANALYZE_SOURCES", {"capabilities": capability_module})
    monkeypatch.setattr(analyzer, "output_results", lambda **kwargs: None)

    payload = analyzer.run_analysis(output_format="json", sources=["capabilities"], top=10)

    assert payload["results"] == []
    assert any(item["code"] == "missing_getcap" for item in payload["metadata"]["limitations"])


def test_run_analysis_saves_full_filtered_results_while_terminal_display_honors_top(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        analyzer,
        "ANALYZE_SOURCES",
        {
            "systemd": lambda: [
                _finding("/tmp/one.service", score=100, severity="CRITICAL", reason="one"),
                _finding("/tmp/two.service", score=90, severity="HIGH", reason="two"),
                _finding("/tmp/three.service", score=80, severity="HIGH", reason="three"),
            ],
        },
    )

    captured: dict[str, object] = {}

    def fake_output_results(
        *,
        mode: str,
        results: list[dict[str, object]],
        output_format: str,
        output_path,
        metadata,
        display_results=None,
    ):
        captured["mode"] = mode
        captured["results"] = results
        captured["display_results"] = display_results
        captured["metadata"] = metadata

    monkeypatch.setattr(analyzer, "output_results", fake_output_results)

    payload = analyzer.run_analysis(
        output_format="json",
        sources=["systemd"],
        top=2,
    )

    assert payload["summary"]["filtered_finding_count"] == 3
    assert payload["summary"]["saved_finding_count"] == 3
    assert payload["summary"]["displayed_finding_count"] == 2
    assert payload["summary"]["display_truncated"] is True
    assert len(payload["results"]) == 2
    assert len(payload["all_results"]) == 3
    assert all(item["finding_id"].startswith("TX-SYSTEMD-") for item in payload["all_results"])
    assert captured["results"] == payload["all_results"]
    assert captured["display_results"] == payload["results"]
    assert any(item["code"] == "terminal_truncation" for item in payload["metadata"]["limitations"])
    assert not any(item["code"] == "results_filtered" for item in payload["metadata"]["limitations"])


def test_run_analysis_does_not_report_user_filters_for_default_top_and_sort_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        analyzer,
        "ANALYZE_SOURCES",
        {
            "systemd": lambda: [
                _finding("/tmp/one.service", score=100, severity="CRITICAL", reason="one"),
                _finding("/tmp/two.service", score=90, severity="HIGH", reason="two"),
            ],
        },
    )
    monkeypatch.setattr(analyzer, "output_results", lambda **kwargs: None)

    payload = analyzer.run_analysis(
        output_format="json",
        sources=["systemd"],
    )

    limitation_codes = {item["code"] for item in payload["metadata"]["limitations"]}
    assert "results_filtered" not in limitation_codes


def test_run_analysis_merges_overlapping_shell_and_environment_hits_on_same_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path_value = "/etc/profile.d/system-shell-env.sh"
    preview = "line 1: export BASH_ENV=/tmp/.pulse-meta/runtime-helper"

    monkeypatch.setattr(
        analyzer,
        "ANALYZE_SOURCES",
        {
            "shell_profiles": lambda: [
                _finding(
                    path_value,
                    score=95,
                    reason="Shell profile sets variable to temp path",
                    preview=preview,
                    tags=["system-scope", "user-persistence"],
                )
            ],
            "environment_hooks": lambda: [
                _finding(
                    path_value,
                    score=85,
                    reason="Environment hook defines sensitive variable using hidden path",
                    preview=preview,
                    tags=["system-scope", "user-persistence", "hidden"],
                )
            ],
        },
    )
    monkeypatch.setattr(analyzer, "output_results", lambda **kwargs: None)

    payload = analyzer.run_analysis(
        output_format="json",
        sources=["shell_profiles", "environment_hooks"],
        top=10,
    )

    assert payload["summary"]["filtered_finding_count"] == 1
    assert payload["summary"]["deduplicated_count"] == 1
    assert payload["results"][0]["dedupe"]["merged_count"] == 2


def test_derive_tags_does_not_label_sync_path_as_network_retrieval() -> None:
    tags = analyzer._derive_tags(
        source="shell_profiles",
        path_value="/etc/profile.d/system-prompt-cache.sh",
        reason="Shell profile uses PROMPT_COMMAND with suspicious behavior",
        preview="line 1: export PROMPT_COMMAND='/var/tmp/.cache-sync/net-policy-sync >/dev/null 2>&1'",
    )

    assert "network-retrieval" not in tags


def test_cli_main_dispatches_repaired_analyze_contract_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: dict[str, object] = {}

    monkeypatch.setattr(cli, "show_startup_banner", lambda duration=5.0: calls.__setitem__("banner", duration))
    monkeypatch.setattr(cli, "run_analysis", lambda **kwargs: calls.setdefault("analysis", kwargs))

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "tenax",
            "analyze",
            "--banner",
            "--severity",
            "high",
            "--sort",
            "severity",
            "--only-writable",
            "--only-existing",
            "--scope",
            "user",
            "--source",
            "ssh,systemd",
            "--path-contains",
            ".ssh",
            "--top",
            "7",
            "--format",
            "json",
            "--root-prefix",
            "/mnt/image",
        ],
    )

    cli.main()

    assert calls["banner"] == 5.0
    assert calls["analysis"] == {
        "output_path": None,
        "output_format": "json",
        "top": 7,
        "severity": "HIGH",
        "sources": ["ssh", "systemd"],
        "path_contains": ".ssh",
        "only_writable": True,
        "only_existing": True,
        "scope": "user",
        "sort_by": "severity",
        "quiet": False,
        "verbose": False,
        "root_prefix": Path("/mnt/image"),
    }


def test_cli_collect_requires_explicit_mode_and_dispatches_new_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: dict[str, object] = {}
    parser = cli.build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["collect"])

    monkeypatch.setattr(cli, "run_collection", lambda **kwargs: calls.setdefault("collection", kwargs))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "tenax",
            "collect",
            "--mode",
            "structured",
            "--archive",
            "--modules",
            "ssh,pam",
            "--no-follow-references",
            "--root-prefix",
            "/mnt/image",
        ],
    )

    cli.main()

    assert calls["collection"] == {
        "output_path": None,
        "hash_files": True,
        "mode": "structured",
        "modules": ["ssh", "pam"],
        "follow_references": False,
        "archive": True,
        "baseline_name": None,
        "max_file_size": 2 * 1024 * 1024,
        "max_hash_size": 10 * 1024 * 1024,
        "max_reference_depth": 2,
        "exclude_patterns": (),
        "root_prefix": Path("/mnt/image"),
    }


def test_cli_supports_version_and_module_discovery(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = cli.build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["--version"])

    monkeypatch.setattr(sys, "argv", ["tenax", "list-modules", "--mode", "analyze"])
    cli.main()

    output = capsys.readouterr().out
    assert "Analyze modules:" in output
    assert "systemd" in output


def test_run_analysis_scans_all_discovered_users_for_user_scoped_modules(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target_root = tmp_path / "mounted-root"
    (target_root / "etc").mkdir(parents=True)
    (target_root / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
        "bob:x:1001:1001:Bob:/home/bob:/bin/bash\n",
        encoding="utf-8",
    )

    alice_unit = target_root / "home" / "alice" / ".config" / "systemd" / "user" / "evil.service"
    alice_unit.parent.mkdir(parents=True)
    alice_unit.write_text("[Service]\nExecStart=/tmp/payload.sh\n", encoding="utf-8")

    bob_unit = target_root / "home" / "bob" / ".config" / "systemd" / "user" / "benign.service"
    bob_unit.parent.mkdir(parents=True)
    bob_unit.write_text("[Service]\nExecStart=/usr/bin/true\n", encoding="utf-8")

    monkeypatch.setattr(analyzer, "output_results", lambda **kwargs: None)

    payload = analyzer.run_analysis(
        output_format="json",
        sources=["systemd"],
        root_prefix=target_root,
        top=20,
    )

    assert payload["results"]
    finding = next(item for item in payload["results"] if item["path"] == "/home/alice/.config/systemd/user/evil.service")
    assert_analyze_finding_shape(finding)
    assert finding["host_path"] == str(alice_unit)
    assert payload["metadata"]["scope"]["root_prefix"] == str(target_root)
    assert payload["metadata"]["scope"]["all_users"] == ["root", "alice", "bob"]
    assert any(item["code"] == "target_root" for item in payload["metadata"]["limitations"])
    assert any(item["code"] == "user_enumeration" for item in payload["metadata"]["limitations"])
