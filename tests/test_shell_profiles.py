from __future__ import annotations

from tenax.checks import shell_profiles


def test_shell_profiles_ignores_benign_profile_d_admin_logic(tmp_path) -> None:
    artifact = tmp_path / "Z99-cloud-locale-test.sh"
    artifact.write_text(
        "printf \"   sudo touch /var/lib/cloud/instance/locale-check.skip\\n\"\n",
        encoding="utf-8",
    )

    assert shell_profiles._analyze_file(artifact) is None


def test_shell_profiles_ignores_benign_xsession_probe_logic(tmp_path) -> None:
    artifact = tmp_path / "im-config_wayland.sh"
    artifact.write_text(
        "if [ -r /etc/X11/Xsession.d/70im-config_launch ]; then\n"
        "    export XMODIFIERS=@im=ibus\n"
        "fi\n",
        encoding="utf-8",
    )

    assert shell_profiles._analyze_file(artifact) is None


def test_shell_profiles_still_detects_temp_path_prompt_hook(tmp_path) -> None:
    artifact = tmp_path / ".bashrc"
    artifact.write_text(
        "PROMPT_COMMAND='/tmp/.cache/persist.sh'\n",
        encoding="utf-8",
    )

    finding = shell_profiles._analyze_file(artifact)

    assert finding is not None
    assert any("prompt_command" in reason.lower() or "prompt command" in reason.lower() for reason in finding["reasons"])


def test_shell_profiles_detects_direct_user_profile_source_hook(tmp_path) -> None:
    artifact = tmp_path / ".bash_profile"
    artifact.write_text(
        "source /home/analyst/.cache/.profile-hook\n",
        encoding="utf-8",
    )

    finding = shell_profiles._analyze_file(artifact)

    assert finding is not None
    assert any("user-controlled path" in reason.lower() for reason in finding["reasons"])
