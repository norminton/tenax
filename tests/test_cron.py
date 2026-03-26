from __future__ import annotations

import hashlib

from tenax.checks import cron

from .conftest import assert_basic_module_finding


def test_cron_fixture_detects_suspicious_execution_chain(fixture_file_factory) -> None:
    artifact = fixture_file_factory("cron", "suspicious.cron", target_name="suspicious.cron")

    finding = cron._analyze_file(artifact)

    assert finding is not None
    assert_basic_module_finding(finding, artifact)
    assert finding["severity"] in {"HIGH", "CRITICAL"}
    assert any("downloader output directly into an interpreter" in reason.lower() for reason in finding["reasons"])
    assert "line 3:" in finding["preview"]


def test_cron_fixture_ignores_benign_job(fixture_file_factory) -> None:
    artifact = fixture_file_factory("cron", "benign.cron", target_name="benign.cron")

    assert cron._analyze_file(artifact) is None


def test_cron_collect_record_includes_hash_when_requested(fixture_file_factory) -> None:
    artifact = fixture_file_factory("cron", "suspicious.cron", target_name="collect.cron")

    record = cron._build_collect_record(artifact, hash_files=True)

    assert record["path"] == str(artifact)
    assert record["exists"] is True
    assert record["sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
