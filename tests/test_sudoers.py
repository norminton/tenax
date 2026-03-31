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


def test_sudoers_detects_nopasswd_user_controlled_command_without_extension(tmp_path) -> None:
    artifact = tmp_path / "appsvc"
    artifact.write_text(
        "appsvc ALL=(root) NOPASSWD: /home/appsvc/.local/bin/.wrap-login\n",
        encoding="utf-8",
    )

    finding = sudoers._analyze_file(artifact)

    assert finding is not None
    assert_basic_module_finding(finding, artifact)
    assert any("NOPASSWD" in reason for reason in finding["reasons"])
    assert any("user-controlled command path" in reason for reason in finding["reasons"])


def test_sudoers_detects_delegated_command_list_with_interpreter_and_user_payload(tmp_path) -> None:
    artifact = tmp_path / "db-session"
    artifact.write_text(
        "dbadmin ALL=(root) NOPASSWD: /usr/bin/python3 /home/dbadmin/.local/share/.session-helper\n",
        encoding="utf-8",
    )

    finding = sudoers._analyze_file(artifact)

    assert finding is not None
    assert_basic_module_finding(finding, artifact)
    assert any("delegated command list" in reason.lower() or "user-controlled command path" in reason.lower() for reason in finding["reasons"])
