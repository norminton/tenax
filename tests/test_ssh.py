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


def test_ssh_detects_valid_authorized_keys_command_option_with_user_path(tmp_path) -> None:
    artifact = tmp_path / "authorized_keys"
    artifact.write_text(
        'command="/home/appsvc/.local/bin/.wrap-login",restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey appsvc@lab\n',
        encoding="utf-8",
    )

    finding = ssh._analyze_file(artifact)

    assert finding is not None
    assert_basic_module_finding(finding, artifact)
    assert any("command=" in reason for reason in finding["reasons"])
    assert any("high-risk path" in reason.lower() for reason in finding["reasons"])


def test_ssh_detects_command_only_authorized_keys_option_line_from_corpus_style(tmp_path) -> None:
    artifact = tmp_path / "authorized_keys"
    artifact.write_text(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPersist analyst@tenax-lab\n"
        'command="/home/analyst/.cache/.profile-hook",no-agent-forwarding,no-port-forwarding '
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPersist2 analyst-admin@tenax-lab\n",
        encoding="utf-8",
    )

    finding = ssh._analyze_file(artifact)

    assert finding is not None
    assert_basic_module_finding(finding, artifact)
    assert any("user-controlled path" in reason.lower() for reason in finding["reasons"])
