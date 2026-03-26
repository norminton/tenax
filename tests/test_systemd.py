from __future__ import annotations

from tenax.checks import systemd

from .conftest import assert_basic_module_finding


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
