import json
from pathlib import Path

import pytest

from observation_db_helpers import Database
from backend.services.observation_fabric import ObservationStore


def live_sigma_match():
    return {
        "detection_basis": "rule_fired_against_osquery_telemetry",
        "level": "medium",
        "matched_event": {
            "action": "added",
            "osquery_pack": "crontab_snapshot",
            "timestamp": "Wed Apr 15 08:48:00 2026 UTC",
            "unix_time": "1776242880",
        },
        "rule_file": "file_event_lnx_persistence_cron_files.yml",
        "rule_id": "6c4e2f43-d94d-4ead-b64d-97e53fa2bd05",
        "rule_sha256": "",
        "source": "SigmaHQ/sigma community rules",
        "status": "test",
        "technique": "T1053.003",
        "timestamp": "2026-04-15T08:48:00+00:00",
        "title": "Persistence Via Cron Files",
    }


def contextual_sigma_match():
    return {
        "analytic_id": "SIG-21e44d78-95e7-421b-a464-ffd8395659c4",
        "live_sigma_evaluation": False,
        "match_count": 1,
        "match_type": "contextual",
        "matched": True,
        "rule_file": "proxy_ua_empty.yml",
        "rule_id": "21e44d78-95e7-421b-a464-ffd8395659c4",
        "rule_sha256": "cdedf5789bbb009086b306bc6672490d9b28036bb0a8b464f3a5671b50aab36e",
        "source_id": "21e44d78-95e7-421b-a464-ffd8395659c4",
        "supporting_event_ids": ["osq-1777103337-atomic_t1001_003_b1"],
        "title": "HTTP Request With Empty User Agent",
    }


def test_live_sigma_match_maps_to_integration_evidence():
    from backend.services.integration_observation_fabric import (
        sigma_match_to_integration_evidence,
    )

    doc = sigma_match_to_integration_evidence(
        live_sigma_match(),
        technique_id=None,
        source_path="evidence-bundle/analytics/sigma_matches.json",
    )

    assert doc["schema"] == "seraph.integration.evidence.v1"
    assert doc["integration_name"] == "sigma"
    assert doc["evidence_type"] == "sigma_rule_match"
    assert doc["technique_id"] == "T1053.003"
    assert doc["payload"]["rule_id"] == "6c4e2f43-d94d-4ead-b64d-97e53fa2bd05"
    assert doc["payload"]["title"] == "Persistence Via Cron Files"
    assert doc["payload"]["detection_basis"] == "rule_fired_against_osquery_telemetry"
    assert doc["payload"]["source_path"] == "evidence-bundle/analytics/sigma_matches.json"
    assert doc["world_fanout_status"] == "pending"


def test_contextual_sigma_match_uses_path_technique():
    from backend.services.integration_observation_fabric import (
        sigma_match_to_integration_evidence,
    )

    doc = sigma_match_to_integration_evidence(
        contextual_sigma_match(),
        technique_id="T1001",
        source_path="evidence-bundle/techniques/T1001/TVR-x/analytics/sigma_matches.json",
    )

    assert doc["technique_id"] == "T1001"
    assert doc["payload"]["rule_id"] == "21e44d78-95e7-421b-a464-ffd8395659c4"
    assert doc["payload"]["match_type"] == "contextual"
    assert doc["payload"]["live_sigma_evaluation"] is False


def test_sigma_loader_handles_live_and_contextual_files(tmp_path):
    from backend.services.integration_observation_fabric import (
        load_sigma_matches_integration_evidence,
    )

    live = tmp_path / "sigma_matches.json"
    live.write_text(json.dumps([live_sigma_match()]))

    contextual = tmp_path / "evidence-bundle" / "techniques" / "T1001" / "TVR-T1001-x" / "analytics"
    contextual.mkdir(parents=True)
    contextual_file = contextual / "sigma_matches.json"
    contextual_file.write_text(json.dumps([contextual_sigma_match()]))

    docs = load_sigma_matches_integration_evidence([live, contextual_file])

    assert len(docs) == 2
    assert {doc["technique_id"] for doc in docs} == {"T1053.003", "T1001"}
    assert {doc["payload"]["rule_id"] for doc in docs} == {
        "6c4e2f43-d94d-4ead-b64d-97e53fa2bd05",
        "21e44d78-95e7-421b-a464-ffd8395659c4",
    }


@pytest.mark.asyncio
async def test_sigma_ingest_persists_and_claims_observations(tmp_path):
    from backend.services.integration_observation_fabric import IntegrationObservationBridge

    db = Database()
    await ObservationStore(db).ensure_indexes()

    path = tmp_path / "sigma_matches.json"
    path.write_text(json.dumps([live_sigma_match()]))

    result = await IntegrationObservationBridge(db).ingest_sigma_matches([path])

    assert result["ingested"] is True
    assert result["loaded"] == 1
    assert result["inserted"] == 1
    assert result["claimed"] == 1
    source = await db.integration_evidence.find_one({"integration_name": "sigma"})
    obs = await db.canonical_observations.find_one({"witness": "integration_evidence"})
    assert source["world_fanout_status"] == "observed"
    assert source["observation_id"] == obs["observation_id"]
    assert obs["entity_refs"] == ["mitre:T1053.003"]
    assert obs["source_event_type"] == "sigma_rule_match"


@pytest.mark.asyncio
async def test_sigma_ingest_is_idempotent(tmp_path):
    from backend.services.integration_observation_fabric import IntegrationObservationBridge

    db = Database()
    await ObservationStore(db).ensure_indexes()

    path = tmp_path / "sigma_matches.json"
    path.write_text(json.dumps([live_sigma_match()]))

    first = await IntegrationObservationBridge(db).ingest_sigma_matches([path])
    second = await IntegrationObservationBridge(db).ingest_sigma_matches([path])

    assert first["inserted"] == 1
    assert second["inserted"] == 0
    assert second["duplicates"] == 1
    assert await db.integration_evidence.count_documents({}) == 1
    assert await db.canonical_observations.count_documents({}) == 1
