from __future__ import annotations

from tenax.checks import sudoers

from .conftest import assert_basic_module_finding


def test_sudoers_fixture_detects_privilege_and_execution_risk(fixture_file_factory) -> None:
    artifact = fixture_file_factory("sudoers", "suspicious.sudoers", target_name="sudoers")

    finding = sudoers._analyze_file(artifact)

    assert finding is not None
    assert_basic_module_finding(finding, artifact)
    assert finding["severity"] in {"HIGH", "CRITICAL"}
    assert any("NOPASSWD" in reason for reason in finding["reasons"])
    assert any("Cmnd_Alias BACKDOOR references a temporary path" in reason for reason in finding["reasons"])


def test_sudoers_fixture_ignores_standard_root_policy(fixture_file_factory) -> None:
    artifact = fixture_file_factory("sudoers", "benign.sudoers", target_name="sudoers")

    assert sudoers._analyze_file(artifact) is None
