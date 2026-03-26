from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tenax import collector

from .conftest import assert_manifest_artifact_shape, assert_reference_shape


def _latest_collection_dir(base: Path) -> Path:
    return sorted(base.glob("collect_*"))[-1]


def test_run_collection_requires_explicit_supported_mode(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="collection mode is required"):
        collector.run_collection(output_path=tmp_path / "out")

    with pytest.raises(ValueError, match="unsupported collection mode"):
        collector.run_collection(output_path=tmp_path / "out", mode="parsed")


def test_run_collection_structured_mode_writes_investigator_grade_manifest_and_references(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    direct_artifact = tmp_path / "sshd_config"
    referenced_artifact = tmp_path / "fetch-keys.sh"
    referenced_artifact.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    direct_artifact.write_text(
        f"AuthorizedKeysCommand {referenced_artifact}\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        collector,
        "CHECK_REGISTRY",
        {
            "ssh": lambda **kwargs: [
                {"path": str(direct_artifact), "owner": "root", "permissions": "0o644"},
            ]
        },
    )

    collector.run_collection(
        output_path=tmp_path / "out",
        modules=["ssh"],
        mode="structured",
        hash_files=True,
        follow_references=False,
        max_reference_depth=2,
    )

    run_dir = _latest_collection_dir(tmp_path / "out")
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    artifacts = json.loads((run_dir / "artifacts.json").read_text(encoding="utf-8"))
    references = json.loads((run_dir / "references.json").read_text(encoding="utf-8"))
    hashes_lines = (run_dir / "hashes.txt").read_text(encoding="utf-8").splitlines()

    assert manifest["schema_version"] == "2.0"
    assert manifest["mode"] == "structured"
    assert manifest["collection_profile"]["parsed_detail_level"] == "structured"
    assert manifest["summary"]["artifact_count"] == 2
    assert manifest["summary"]["required_reference_count"] == 1
    assert manifest["summary"]["followed_required_reference_count"] == 1
    assert any(item["code"] == "collection_mode" for item in manifest["limitations"])
    assert (run_dir / "artifacts.json").exists()

    direct_record = next(item for item in artifacts if item["discovery_mode"] == "direct")
    reference_record = next(item for item in artifacts if item["discovery_mode"] == "reference")
    assert_manifest_artifact_shape(direct_record)
    assert_manifest_artifact_shape(reference_record)
    assert direct_record["collection_mode"] == "structured"
    assert direct_record["rationale"]["why_collected"]
    assert direct_record["lineage"]["collection_mode"] == "structured"
    assert reference_record["lineage"]["parent_artifact_id"] == direct_record["id"]
    assert reference_record["module_metadata"]["classification"] in {"execution", "supporting"}

    assert_reference_shape(references[0])
    assert references[0]["followed"] is True
    assert references[0]["collection_required"] is True
    assert references[0]["classification"] in {"execution", "supporting"}

    expected_direct_hash = hashlib.sha256(direct_artifact.read_bytes()).hexdigest()
    expected_reference_hash = hashlib.sha256(referenced_artifact.read_bytes()).hexdigest()
    assert f"{expected_direct_hash}  {direct_artifact}" in hashes_lines
    assert f"{expected_reference_hash}  {referenced_artifact}" in hashes_lines


def test_run_collection_minimal_mode_preserves_artifacts_without_full_text_capture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    direct_artifact = tmp_path / "evil.service"
    referenced_artifact = tmp_path / "payload.sh"
    referenced_artifact.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    direct_artifact.write_text(f"[Service]\nExecStart={referenced_artifact}\n", encoding="utf-8")

    monkeypatch.setattr(
        collector,
        "CHECK_REGISTRY",
        {"systemd": lambda **kwargs: [{"path": str(direct_artifact)}]},
    )

    collector.run_collection(
        output_path=tmp_path / "minimal-out",
        modules=["systemd"],
        mode="minimal",
        hash_files=True,
    )

    run_dir = _latest_collection_dir(tmp_path / "minimal-out")
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["mode"] == "minimal"
    assert manifest["options"]["persist_text_capture"] is False
    assert manifest["options"]["copy_files"] is True
    assert manifest["options"]["copy_references"] is True
    for artifact in manifest["artifacts"]:
        assert artifact["copy_status"]["copied"] is True
        assert artifact["content_capture"]["full_text"] is None
        assert artifact["content_capture"]["truncated_text"] is None


def test_run_collection_evidence_mode_copies_direct_and_reference_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    direct_artifact = tmp_path / "sshd_config"
    referenced_artifact = tmp_path / "reference.sh"
    referenced_artifact.write_text("#!/bin/sh\necho ref\n", encoding="utf-8")
    direct_artifact.write_text(f"AuthorizedKeysCommand {referenced_artifact}\n", encoding="utf-8")

    monkeypatch.setattr(
        collector,
        "CHECK_REGISTRY",
        {"ssh": lambda **kwargs: [{"path": str(direct_artifact), "owner": "root", "permissions": "0o644"}]},
    )

    collector.run_collection(
        output_path=tmp_path / "evidence-out",
        modules=["ssh"],
        mode="evidence",
        hash_files=True,
        follow_references=True,
        max_reference_depth=2,
    )

    run_dir = _latest_collection_dir(tmp_path / "evidence-out")
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["options"]["copy_files"] is True
    assert manifest["options"]["copy_references"] is True
    assert manifest["summary"]["copied_artifact_count"] == 2
    for artifact in manifest["artifacts"]:
        assert artifact["copy_status"]["copied"] is True
        assert Path(artifact["copy_status"]["copied_to"]).exists()


def test_run_collection_surfaces_errors_and_partial_coverage_metadata(tmp_path: Path) -> None:
    collector.run_collection(
        output_path=tmp_path / "error-out",
        modules=["missing-module"],
        mode="structured",
        hash_files=True,
    )

    run_dir = _latest_collection_dir(tmp_path / "error-out")
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    errors = json.loads((run_dir / "errors.json").read_text(encoding="utf-8"))

    assert manifest["summary"]["artifact_count"] == 0
    assert manifest["summary"]["error_count"] == 1
    assert errors == [{"module": "missing-module", "error": "module not registered"}]
    assert any(item["code"] == "collection_errors" for item in manifest["limitations"])


def test_run_collection_root_prefix_preserves_target_lineage_and_root_aware_references(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target_root = tmp_path / "mounted-root"
    (target_root / "etc").mkdir(parents=True)
    (target_root / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
        encoding="utf-8",
    )

    direct_artifact = target_root / "etc" / "ssh" / "sshd_config"
    direct_artifact.parent.mkdir(parents=True)
    referenced_artifact = target_root / "opt" / "payload.sh"
    referenced_artifact.parent.mkdir(parents=True)
    referenced_artifact.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    direct_artifact.write_text("AuthorizedKeysCommand /opt/payload.sh\n", encoding="utf-8")

    monkeypatch.setattr(
        collector,
        "CHECK_REGISTRY",
        {"ssh": lambda **kwargs: [{"path": str(direct_artifact), "owner": "root", "permissions": "0o644"}]},
    )

    collector.run_collection(
        output_path=tmp_path / "rooted-out",
        modules=["ssh"],
        mode="structured",
        hash_files=True,
        follow_references=True,
        root_prefix=target_root,
    )

    run_dir = _latest_collection_dir(tmp_path / "rooted-out")
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    references = json.loads((run_dir / "references.json").read_text(encoding="utf-8"))

    assert manifest["options"]["root_prefix"] == str(target_root)
    assert manifest["scope"]["target_root"] == "/"
    assert any(item["code"] == "target_root" for item in manifest["limitations"])
    assert any(item["code"] == "user_enumeration" for item in manifest["limitations"])

    direct_record = next(item for item in manifest["artifacts"] if item["discovery_mode"] == "direct")
    reference_record = next(item for item in manifest["artifacts"] if item["discovery_mode"] == "reference")

    assert direct_record["path"] == "/etc/ssh/sshd_config"
    assert direct_record["host_path"] == str(direct_artifact)
    assert direct_record["module_metadata"]["target_path"] == "/etc/ssh/sshd_config"

    assert reference_record["path"] == "/opt/payload.sh"
    assert reference_record["host_path"] == str(referenced_artifact)
    assert reference_record["module_metadata"]["target_path"] == "/opt/payload.sh"

    assert references[0]["value"] == "/opt/payload.sh"
    assert references[0]["resolved"] == "/opt/payload.sh"
    assert references[0]["host_resolved"] == str(referenced_artifact)
    assert references[0]["parent_path"] == "/etc/ssh/sshd_config"


def test_run_collection_real_module_expands_user_scoped_paths_under_root_prefix(tmp_path: Path) -> None:
    target_root = tmp_path / "offline-root"
    (target_root / "etc").mkdir(parents=True)
    (target_root / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
        "bob:x:1001:1001:Bob:/home/bob:/bin/bash\n",
        encoding="utf-8",
    )

    alice_profile = target_root / "home" / "alice" / ".bashrc"
    alice_profile.parent.mkdir(parents=True)
    alice_profile.write_text("export PATH=/usr/bin\n", encoding="utf-8")

    bob_profile = target_root / "home" / "bob" / ".profile"
    bob_profile.parent.mkdir(parents=True)
    bob_profile.write_text("export TERM=xterm\n", encoding="utf-8")

    collector.run_collection(
        output_path=tmp_path / "multiuser-out",
        modules=["shell_profiles"],
        mode="minimal",
        hash_files=False,
        follow_references=False,
        root_prefix=target_root,
    )

    run_dir = _latest_collection_dir(tmp_path / "multiuser-out")
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    artifact_paths = {item["path"] for item in manifest["artifacts"]}

    assert "/home/alice/.bashrc" in artifact_paths
    assert "/home/bob/.profile" in artifact_paths
    assert manifest["scope"]["all_users"] == ["root", "alice", "bob"]


def test_run_collection_parsed_outputs_prioritize_high_value_investigator_structures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    systemd_unit = tmp_path / "evil.service"
    systemd_unit.write_text(
        "[Service]\nExecStart=/tmp/payload.sh --flag\nEnvironmentFile=/etc/default/evil\nUser=root\n",
        encoding="utf-8",
    )

    cron_file = tmp_path / "evil.cron"
    cron_file.write_text("* * * * * /tmp/payload.sh\n", encoding="utf-8")

    pam_file = tmp_path / "login"
    pam_file.write_text("auth required pam_exec.so expose_authtok /tmp/pam-payload.sh\n", encoding="utf-8")

    monkeypatch.setattr(
        collector,
        "CHECK_REGISTRY",
        {
            "systemd": lambda **kwargs: [{"path": str(systemd_unit)}],
            "cron": lambda **kwargs: [{"path": str(cron_file)}],
            "pam": lambda **kwargs: [{"path": str(pam_file)}],
        },
    )

    collector.run_collection(
        output_path=tmp_path / "parsed-out",
        modules=["systemd", "cron", "pam"],
        mode="structured",
        hash_files=True,
    )

    run_dir = _latest_collection_dir(tmp_path / "parsed-out")
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))

    systemd_record = next(item for item in manifest["artifacts"] if item["module"] == "systemd")
    cron_record = next(item for item in manifest["artifacts"] if item["module"] == "cron")
    pam_record = next(item for item in manifest["artifacts"] if item["module"] == "pam")

    assert systemd_record["parsed"]["format"] == "systemd-unit"
    assert systemd_record["parsed"]["exec_entries"][0]["paths"] == ["/tmp/payload.sh"]
    assert cron_record["parsed"]["format"] == "cron"
    assert cron_record["parsed"]["jobs"][0]["schedule"] == "* * * * *"
    assert pam_record["parsed"]["format"] == "pam"
    assert pam_record["parsed"]["modules"][0]["module"] == "pam_exec.so"
