import json

import pytest

from observation_db_helpers import Database
from backend.services.observation_fabric import ObservationStore


def tvr_record():
    return {
        "record_type": "technique_validation_record",
        "schema_version": "1.0.0",
        "validation_id": "TVR-T1001-2026-04-27-002",
        "technique": {"attack_id": "T1001", "name": "T1001"},
        "procedure": {
            "procedure_id": "ART-T1001-1",
            "source": "atomic_red_team",
            "test_ref": "atomics/T1001/T1001.yaml#test-1",
        },
        "execution": {
            "started_at": "2026-04-25T07:48:56.596336+00:00",
            "ended_at": "2026-04-25T07:48:56.596336+00:00",
            "executor": "atomic_red_team",
            "status": "completed",
            "exit_code": 0,
            "real_execution": True,
            "run_ids": ["run-001"],
            "job_ids": ["vns-full-sweep"],
        },
        "quality": {
            "analyst_reviewed": True,
            "successful_detections": 1,
            "osquery_status": "matched",
        },
        "integrity": {"record_sha256": "abc123"},
    }


def atomic_stdout_event():
    return {
        "run_id": "run-001",
        "job_id": "vns-full-sweep",
        "job_name": "VNS Full Technique Sweep",
        "finished_at": "2026-04-25T07:48:56.596336+00:00",
        "exit_code": 0,
        "sandbox": "docker-network-none-cap-drop-all",
        "stdout": "Executing test: T1001.003-VNS-Simulation\n[VNS] 1/8 events flagged suspicious\n",
        "stdout_sha256": "416ef887814b654eddb66a82375edbc142fa0ea1bd25ae974d9577670b19661b",
    }


def test_tvr_record_maps_to_integration_evidence():
    from backend.services.integration_observation_fabric import (
        tvr_record_to_integration_evidence,
    )

    doc = tvr_record_to_integration_evidence(
        tvr_record(),
        source_path="evidence-bundle/techniques/T1001/TVR-T1001-2026-04-27-002/tvr.json",
    )

    assert doc["schema"] == "seraph.integration.evidence.v1"
    assert doc["integration_name"] == "tvr"
    assert doc["evidence_type"] == "technique_validation_record"
    assert doc["technique_id"] == "T1001"
    assert doc["timestamp"] == "2026-04-25T07:48:56.596336+00:00"
    assert doc["source_event_id"] == "tvr|technique_validation_record|TVR-T1001-2026-04-27-002"
    assert doc["payload"]["validation_id"] == "TVR-T1001-2026-04-27-002"
    assert doc["payload"]["record_sha256"] == "abc123"


def test_atomic_stdout_maps_to_integration_evidence():
    from backend.services.integration_observation_fabric import (
        atomic_stdout_event_to_integration_evidence,
    )

    doc = atomic_stdout_event_to_integration_evidence(
        atomic_stdout_event(),
        technique_id="T1001",
        validation_id="TVR-T1001-2026-04-27-002",
        source_path="evidence-bundle/techniques/T1001/TVR-T1001-2026-04-27-002/telemetry/atomic_stdout.ndjson",
    )

    assert doc["integration_name"] == "atomic_red_team"
    assert doc["evidence_type"] == "atomic_stdout"
    assert doc["technique_id"] == "T1001"
    assert doc["timestamp"] == "2026-04-25T07:48:56.596336+00:00"
    assert doc["source_event_id"] == "atomic_red_team|atomic_stdout|TVR-T1001-2026-04-27-002|run-001|416ef887814b654eddb66a82375edbc142fa0ea1bd25ae974d9577670b19661b"
    assert doc["payload"]["stdout_sha256"].startswith("416ef887")


@pytest.mark.asyncio
async def test_tvr_ingest_persists_and_claims_canonical_observation(tmp_path):
    from backend.services.integration_observation_fabric import IntegrationObservationBridge

    db = Database()
    await ObservationStore(db).ensure_indexes()

    path = tmp_path / "tvr.json"
    path.write_text(json.dumps(tvr_record()))

    result = await IntegrationObservationBridge(db).ingest_tvr_records([path])

    assert result["inserted"] == 1
    assert result["claimed"] == 1

    source = await db.integration_evidence.find_one({"integration_name": "tvr"})
    obs = await db.canonical_observations.find_one({"witness": "integration_evidence"})

    assert source["world_fanout_status"] == "observed"
    assert obs["source_event_type"] == "technique_validation_record"
    assert obs["source_event_id"] == "tvr|technique_validation_record|TVR-T1001-2026-04-27-002"
    assert obs["entity_refs"] == ["mitre:T1001"]


@pytest.mark.asyncio
async def test_atomic_stdout_ingest_dedupes_and_claims_observation(tmp_path):
    from backend.services.integration_observation_fabric import IntegrationObservationBridge

    db = Database()
    await ObservationStore(db).ensure_indexes()

    path = tmp_path / "atomic_stdout.ndjson"
    line = json.dumps(atomic_stdout_event())
    path.write_text(line + "\n" + line + "\n")

    result = await IntegrationObservationBridge(db).ingest_atomic_stdout(
        [path],
        technique_id="T1001",
        validation_id="TVR-T1001-2026-04-27-002",
    )

    assert result["loaded"] == 1
    assert result["inserted"] == 1
    assert result["claimed"] == 1

    obs = await db.canonical_observations.find_one({"source_event_type": "atomic_stdout"})
    assert obs["entity_refs"] == ["mitre:T1001"]
    assert obs["payload"]["payload"]["run_id"] == "run-001"
