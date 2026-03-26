from __future__ import annotations

from tenax.checks import pam

from .conftest import assert_basic_module_finding


def test_pam_fixture_detects_suspicious_pam_exec(fixture_file_factory) -> None:
    artifact = fixture_file_factory("pam", "suspicious.pam", target_name="login")

    finding = pam._analyze_file(artifact)

    assert finding is not None
    assert_basic_module_finding(finding, artifact)
    assert finding["severity"] in {"HIGH", "CRITICAL"}
    assert any("pam_exec.so references a command path" in reason for reason in finding["reasons"])
    assert any("expose_authtok" in reason for reason in finding["reasons"])


def test_pam_fixture_ignores_benign_stack(fixture_file_factory) -> None:
    artifact = fixture_file_factory("pam", "benign.pam", target_name="common-auth")

    assert pam._analyze_file(artifact) is None
