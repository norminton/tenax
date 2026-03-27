from __future__ import annotations

from tenax import analyzer


def test_run_analysis_suppresses_packaged_persistent_system_timer_noise(
    monkeypatch,
    tmp_path,
) -> None:
    timer = tmp_path / "usr" / "lib" / "systemd" / "system" / "apt-daily.timer"
    timer.parent.mkdir(parents=True)
    timer.write_text(
        "[Timer]\n"
        "OnCalendar=*-*-* 6,18:00\n"
        "Persistent=true\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(analyzer, "output_results", lambda **kwargs: None)

    payload = analyzer.run_analysis(
        output_format="json",
        sources=["systemd"],
        root_prefix=tmp_path,
        top=20,
    )

    assert not any(item["path"] == "/usr/lib/systemd/system/apt-daily.timer" for item in payload["results"])


def test_run_analysis_suppresses_packaged_user_timer_path_noise(
    monkeypatch,
    tmp_path,
) -> None:
    timer = tmp_path / "usr" / "lib" / "systemd" / "user" / "launchpadlib-cache-clean.timer"
    timer.parent.mkdir(parents=True)
    timer.write_text(
        "[Timer]\n"
        "OnStartupSec=5min\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(analyzer, "output_results", lambda **kwargs: None)

    payload = analyzer.run_analysis(
        output_format="json",
        sources=["systemd"],
        root_prefix=tmp_path,
        top=20,
    )

    assert not any(item["path"] == "/usr/lib/systemd/user/launchpadlib-cache-clean.timer" for item in payload["results"])
