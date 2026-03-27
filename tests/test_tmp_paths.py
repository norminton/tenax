from __future__ import annotations

from tenax.checks import tmp_paths

from .conftest import assert_basic_module_finding


def test_tmp_paths_suppresses_tenax_generated_bundle_reports(tmp_path) -> None:
    report = tmp_path / "out" / "collect_20260327_075654" / "summary.txt"
    report.parent.mkdir(parents=True)
    report.write_text(
        "Preview: AuthorizedKeysCommand /tmp/payload.sh\n",
        encoding="utf-8",
    )

    assert tmp_paths._analyze_artifact(report) is None


def test_tmp_paths_suppresses_tenax_collected_copies(tmp_path) -> None:
    collected = (
        tmp_path
        / "out"
        / "collect_20260327_075654"
        / "collected"
        / "systemd"
        / "tmp_path"
        / "evil.service"
    )
    collected.parent.mkdir(parents=True)
    collected.write_text("[Service]\nExecStart=/tmp/payload.sh\n", encoding="utf-8")

    assert tmp_paths._analyze_artifact(collected) is None


def test_tmp_paths_suppresses_pytest_harness_artifacts(tmp_path) -> None:
    artifact = tmp_path / "pytest-of-analyst" / "pytest-5" / "test_case0" / "evil.service"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("[Service]\nExecStart=/tmp/payload.sh\n", encoding="utf-8")

    assert tmp_paths._analyze_artifact(artifact) is None


def test_tmp_paths_does_not_treat_path_assignment_as_execution(tmp_path) -> None:
    artifact = tmp_path / "env-only.cron"
    artifact.write_text("PATH=/tmp/.cache:/usr/bin:/bin\n", encoding="utf-8")

    assert tmp_paths._analyze_file(artifact) is None


def test_tmp_paths_still_detects_real_suspicious_temp_exec(tmp_path) -> None:
    artifact = tmp_path / "evil.service"
    artifact.write_text("[Service]\nExecStart=/tmp/payload.sh\n", encoding="utf-8")

    finding = tmp_paths._analyze_file(artifact)

    assert finding is not None
    assert_basic_module_finding(finding, artifact)
    assert any("executes suspicious command" in reason.lower() for reason in finding["reasons"])
