from __future__ import annotations

from tenax import analyzer
from tenax.checks import systemd

from .conftest import assert_analyze_finding_shape, assert_basic_module_finding


def test_systemd_fixture_detects_temp_exec_and_ld_preload(fixture_file_factory) -> None:
    artifact = fixture_file_factory("systemd", "suspicious.service", target_name="evil.service")

    finding = systemd._analyze_file(artifact)

    assert finding is not None
    assert_basic_module_finding(finding, artifact)
    assert finding["severity"] in {"HIGH", "CRITICAL"}
    assert any("temporary path" in reason.lower() for reason in finding["reasons"])
    assert any("ld preload" in reason.lower() for reason in finding["reasons"])


def test_systemd_fixture_ignores_benign_unit(fixture_file_factory) -> None:
    artifact = fixture_file_factory("systemd", "benign.service", target_name="cleanup.service")

    assert systemd._analyze_file(artifact) is None


def test_systemd_ignores_packaged_usr_libexec_user_service(tmp_path) -> None:
    artifact = tmp_path / "xdg-document-portal.service"
    artifact.write_text(
        "[Unit]\n"
        "Description=Portal\n\n"
        "[Service]\n"
        "ExecStart=/usr/libexec/xdg-document-portal\n",
        encoding="utf-8",
    )

    assert systemd._analyze_file(artifact) is None


def test_systemd_ignores_benign_chmod_log_maintenance(tmp_path) -> None:
    artifact = tmp_path / "dmesg.service"
    artifact.write_text(
        "[Service]\n"
        "ExecStart=/usr/bin/dmesg --follow\n"
        "ExecStartPost=/bin/chmod 0640 /var/log/dmesg\n",
        encoding="utf-8",
    )

    assert systemd._analyze_file(artifact) is None


def test_systemd_still_detects_suspicious_temp_payload_permission_staging(tmp_path) -> None:
    artifact = tmp_path / "stager.service"
    artifact.write_text(
        "[Service]\n"
        "ExecStartPre=/bin/chmod 0777 /tmp/.cache/persist.sh\n"
        "ExecStart=/tmp/.cache/persist.sh\n",
        encoding="utf-8",
    )

    finding = systemd._analyze_file(artifact)

    assert finding is not None
    assert_basic_module_finding(finding, artifact)
    assert finding["severity"] in {"HIGH", "CRITICAL"}
    assert any("weakens permissions" in reason.lower() for reason in finding["reasons"])
    assert any("temporary path" in reason.lower() for reason in finding["reasons"])


def test_run_analysis_marks_packaged_systemd_user_units_as_user_scope_without_root_execution(
    monkeypatch,
    tmp_path,
) -> None:
    unit = tmp_path / "usr" / "lib" / "systemd" / "user" / "evil.service"
    unit.parent.mkdir(parents=True)
    unit.write_text("[Service]\nExecStart=/tmp/payload.sh\n", encoding="utf-8")

    monkeypatch.setattr(analyzer, "output_results", lambda **kwargs: None)

    payload = analyzer.run_analysis(output_format="json", sources=["systemd"], root_prefix=tmp_path, top=20)

    finding = next(item for item in payload["results"] if item["path"] == "/usr/lib/systemd/user/evil.service")
    assert_analyze_finding_shape(finding)
    assert finding["scope"] == "user"
    assert "user-scope" in finding["tags"]
    assert "system-scope" not in finding["tags"]
    assert "root-execution" not in finding["tags"]
