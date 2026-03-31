from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from tenax.checks import at_jobs, autostart_hooks, capabilities, containers, environment_hooks, ld_preload, network_hooks, rc_init

from .conftest import assert_basic_module_finding, fixture_path


def _copy_fixture(source: Path, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    destination.chmod(0o644)
    return destination


def _set_root_owned_stat(monkeypatch: pytest.MonkeyPatch, module, target: Path) -> None:
    real_stat = target.stat()
    original_private = getattr(module, "_safe_stat", None)
    original_public = getattr(module, "safe_stat", None)

    def fake_stat(path):
        if Path(path) == target:
            return SimpleNamespace(
                st_mode=real_stat.st_mode,
                st_uid=0,
                st_gid=0,
                st_size=real_stat.st_size,
                st_ino=real_stat.st_ino,
                st_mtime=real_stat.st_mtime,
                st_ctime=real_stat.st_ctime,
            )
        if original_private is not None:
            return original_private(path)
        if original_public is not None:
            return original_public(path)
        return Path(path).stat()

    if hasattr(module, "_safe_stat"):
        monkeypatch.setattr(module, "_safe_stat", fake_stat)
    if hasattr(module, "safe_stat"):
        monkeypatch.setattr(module, "safe_stat", fake_stat)


@pytest.mark.parametrize(
    ("module", "path_attr", "fixture_dir", "file_name"),
    [
        (autostart_hooks, "AUTOSTART_PATHS", "autostart_hooks", "suspicious.desktop"),
        (ld_preload, "LD_PRELOAD_PATHS", "ld_preload", "suspicious.conf"),
        (environment_hooks, "ENVIRONMENT_HOOK_PATHS", "environment_hooks", "suspicious.sh"),
        (network_hooks, "NETWORK_HOOK_PATHS", "network_hooks", "suspicious.conf"),
        (rc_init, "RC_PATHS", "rc_init", "suspicious.rc"),
        (at_jobs, "AT_JOB_PATHS", "at_jobs", "suspicious.job"),
        (containers, "CONTAINER_PATHS", "containers", "suspicious.yml"),
    ],
)
def test_modules_detect_realistic_suspicious_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    module,
    path_attr: str,
    fixture_dir: str,
    file_name: str,
) -> None:
    fixture = fixture_path(fixture_dir, file_name)
    if path_attr in {"AUTOSTART_PATHS"}:
        watched_dir = tmp_path / fixture_dir
        target = _copy_fixture(fixture, watched_dir / file_name)
        monkeypatch.setattr(module, path_attr, [watched_dir])
    else:
        target = _copy_fixture(fixture, tmp_path / file_name)
        monkeypatch.setattr(module, path_attr, [target])
        _set_root_owned_stat(monkeypatch, module, target)

    findings = getattr(module, [name for name in dir(module) if name.startswith("analyze_")][0])()

    assert findings
    assert_basic_module_finding(findings[0], target)


@pytest.mark.parametrize(
    ("module", "path_attr", "fixture_dir", "file_name"),
    [
        (autostart_hooks, "AUTOSTART_PATHS", "autostart_hooks", "benign.desktop"),
        (ld_preload, "LD_PRELOAD_PATHS", "ld_preload", "benign.conf"),
        (environment_hooks, "ENVIRONMENT_HOOK_PATHS", "environment_hooks", "benign.sh"),
        (network_hooks, "NETWORK_HOOK_PATHS", "network_hooks", "benign.conf"),
        (rc_init, "RC_PATHS", "rc_init", "benign.rc"),
        (at_jobs, "AT_JOB_PATHS", "at_jobs", "benign.job"),
        (containers, "CONTAINER_PATHS", "containers", "benign.yml"),
    ],
)
def test_modules_suppress_benign_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    module,
    path_attr: str,
    fixture_dir: str,
    file_name: str,
) -> None:
    fixture = fixture_path(fixture_dir, file_name)
    if path_attr in {"AUTOSTART_PATHS"}:
        watched_dir = tmp_path / fixture_dir
        _copy_fixture(fixture, watched_dir / file_name)
        monkeypatch.setattr(module, path_attr, [watched_dir])
    else:
        target = _copy_fixture(fixture, tmp_path / file_name)
        monkeypatch.setattr(module, path_attr, [target])
        _set_root_owned_stat(monkeypatch, module, target)

    findings = getattr(module, [name for name in dir(module) if name.startswith("analyze_")][0])()

    assert findings == []


@pytest.mark.parametrize(
    ("module", "path_attr", "fixture_dir", "file_name"),
    [
        (autostart_hooks, "AUTOSTART_PATHS", "autostart_hooks", "suspicious.desktop"),
        (ld_preload, "LD_PRELOAD_PATHS", "ld_preload", "suspicious.conf"),
        (environment_hooks, "ENVIRONMENT_HOOK_PATHS", "environment_hooks", "suspicious.sh"),
        (network_hooks, "NETWORK_HOOK_PATHS", "network_hooks", "suspicious.conf"),
        (rc_init, "RC_PATHS", "rc_init", "suspicious.rc"),
        (at_jobs, "AT_JOB_PATHS", "at_jobs", "suspicious.job"),
        (containers, "CONTAINER_PATHS", "containers", "suspicious.yml"),
    ],
)
def test_modules_collect_fixture_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    module,
    path_attr: str,
    fixture_dir: str,
    file_name: str,
) -> None:
    fixture = fixture_path(fixture_dir, file_name)
    if path_attr in {"AUTOSTART_PATHS"}:
        watched_dir = tmp_path / fixture_dir
        target = _copy_fixture(fixture, watched_dir / file_name)
        monkeypatch.setattr(module, path_attr, [watched_dir])
    else:
        target = _copy_fixture(fixture, tmp_path / file_name)
        monkeypatch.setattr(module, path_attr, [target])
        _set_root_owned_stat(monkeypatch, module, target)

    artifacts = getattr(module, [name for name in dir(module) if name.startswith("collect_")][0])(hash_files=True)

    assert artifacts
    assert artifacts[0]["path"] == str(target)


def test_capabilities_parsing_and_scoring_without_live_getcap(monkeypatch: pytest.MonkeyPatch) -> None:
    parsed = capabilities._parse_getcap_line("/tmp/persist-helper = cap_setuid,cap_net_bind_service+ep")

    assert parsed is not None
    path_obj, capabilities_text = parsed
    assert str(path_obj) == "/tmp/persist-helper"
    assert capabilities._extract_capability_names(capabilities_text) == ["cap_setuid", "cap_net_bind_service"]

    monkeypatch.setattr(
        capabilities,
        "safe_stat",
        lambda path: SimpleNamespace(st_mode=0o100777, st_uid=1001),
    )
    finding = capabilities._analyze_capability_record(path_obj, capabilities_text)

    assert finding is not None
    assert finding["severity"] in {"HIGH", "CRITICAL"}
    assert "capability" in finding["reason"].lower() or "capabilities" in " ".join(finding["reasons"]).lower()


def test_capabilities_benign_assignment_is_suppressed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        capabilities,
        "safe_stat",
        lambda path: SimpleNamespace(st_mode=0o100755, st_uid=0),
    )

    benign = capabilities._analyze_capability_record(Path("/usr/bin/ping"), "cap_net_bind_service+ep")

    assert benign is None


def test_ld_preload_detects_raw_shared_object_reference_in_ld_so_preload(tmp_path: Path) -> None:
    artifact = tmp_path / "ld.so.preload"
    artifact.write_text("/var/tmp/.cache-sync/libnss-stage.so\n", encoding="utf-8")

    finding = ld_preload._analyze_file(artifact)

    assert finding is not None
    assert_basic_module_finding(finding, artifact)
    assert any("shared object path" in reason.lower() or "temporary path" in reason.lower() for reason in finding["reasons"])


def test_containers_ignores_plain_systemd_unit_without_container_context(tmp_path: Path) -> None:
    artifact = tmp_path / "cleanup.service"
    artifact.write_text(
        "[Unit]\nDescription=cleanup\n\n[Service]\nExecStart=/usr/local/bin/cleanup-old-downloads\n",
        encoding="utf-8",
    )

    assert containers._analyze_file(artifact) is None
