from __future__ import annotations

from tenax.checks import ssh

from .conftest import assert_basic_module_finding


def test_ssh_fixture_detects_suspicious_authorized_keys_behavior(fixture_file_factory) -> None:
    artifact = fixture_file_factory("ssh", "suspicious_authorized_keys", target_name="authorized_keys")

    finding = ssh._analyze_file(artifact)

    assert finding is not None
    assert_basic_module_finding(finding, artifact)
    assert finding["severity"] in {"HIGH", "CRITICAL"}
    assert any("command=" in reason or "LD preload" in reason for reason in finding["reasons"])
    assert "line 1:" in finding["preview"]


def test_ssh_fixture_ignores_benign_authorized_keys_even_when_non_root_owned(fixture_file_factory) -> None:
    artifact = fixture_file_factory("ssh", "benign_authorized_keys", target_name="authorized_keys")

    assert ssh._analyze_file(artifact) is None
