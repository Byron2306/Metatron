import pytest

from observation_db_helpers import Database
from backend.services.observation_fabric import ObservationStore


def completed_job(tool="zeek", technique_id="T1001"):
    return {
        "id": "job-001",
        "tool": tool,
        "status": "completed",
        "created_at": "2026-10-11T09:36:44.128686",
        "updated_at": "2026-10-11T09:36:45.128686",
        "params": {"action": "analyze", "runtime_target": "server"},
        "result": {
            "action": "analyze",
            "result": {
                "available": True,
                "mitre_techniques": [technique_id],
                "finding_count": 1,
            },
        },
    }


def test_integration_tool_result_maps_to_integration_evidence():
    from backend.services.integration_observation_fabric import (
        integration_tool_result_to_integration_evidence,
    )

    docs = integration_tool_result_to_integration_evidence(completed_job("zeek", "T1001"))

    assert len(docs) == 1
    doc = docs[0]
    assert doc["schema"] == "seraph.integration.evidence.v1"
    assert doc["integration_name"] == "zeek"
    assert doc["evidence_type"] == "integration_tool_result"
    assert doc["technique_id"] == "T1001"
    assert doc["payload"]["job_id"] == "job-001"
    assert doc["payload"]["action"] == "analyze"
    assert doc["world_fanout_status"] == "pending"


def test_integration_tool_status_without_technique_is_not_attack_evidence():
    from backend.services.integration_observation_fabric import (
        integration_tool_result_to_integration_evidence,
    )

    job = completed_job("velociraptor", "T1001")
    job["params"] = {"action": "status"}
    job["result"] = {"action": "status", "result": {"available": True}}

    assert integration_tool_result_to_integration_evidence(job) == []


@pytest.mark.asyncio
async def test_completed_tool_jobs_ingest_and_claim_canonical_observation():
    from backend.services.integration_observation_fabric import IntegrationObservationBridge

    db = Database()
    await ObservationStore(db).ensure_indexes()

    await db.integrations_jobs.insert_one(completed_job("zeek", "T1001"))

    result = await IntegrationObservationBridge(db).ingest_completed_tool_jobs(tool="zeek")

    obs = await db.canonical_observations.find_one({"witness": "integration_evidence"})

    assert result["inserted"] == 1
    assert result["claimed"] == 1
    assert obs["source_event_type"] == "integration_tool_result"
    assert obs["source_event_id"] == "zeek|integration_tool_result|T1001|job-001|analyze"
    assert obs["entity_refs"] == ["mitre:T1001"]
    assert obs["payload"]["integration_name"] == "zeek"

@pytest.mark.asyncio
async def test_completed_tool_job_observation_promotes_and_projects_world_event():
    from backend.services.integration_observation_fabric import (
        integration_tool_result_to_integration_evidence,
        integration_evidence_to_observation,
    )
    from backend.services.observation_fabric import (
        PromotionService,
        WorldObservationProjector,
    )

    db = Database()
    await ObservationStore(db).ensure_indexes()

    docs = integration_tool_result_to_integration_evidence(completed_job("zeek", "T1001"))
    assert len(docs) == 1

    obs = integration_evidence_to_observation(docs[0])
    await ObservationStore(db).claim(obs)

    decision = await PromotionService(db).evaluate(obs)
    projection = await WorldObservationProjector(db).project(obs, decision)

    event = await db.world_events.find_one({"type": "observation_promoted"})
    entity = await db.world_entities.find_one({})

    assert decision.promote is True
    assert decision.kind == "novel_material_observation"
    assert projection["projected"] is True
    assert projection["triune_triggered"] is True

    assert event["payload"]["observation_id"] == obs.observation_id
    assert event["payload"]["tvr_receipt_ref"]["witness"] == "integration_evidence"
    assert event["payload"]["tvr_receipt_ref"]["source_event_type"] == "integration_tool_result"
    assert event["triune_triggered"] is True

    assert entity["type"] == "alert"
    assert entity["attributes"]["payload"]["integration_name"] == "zeek"
    assert entity["attributes"]["payload"]["technique_id"] == "T1001"


@pytest.mark.asyncio
async def test_completed_tool_job_repeat_source_event_is_retained_without_duplicate_event():
    from backend.services.integration_observation_fabric import (
        integration_tool_result_to_integration_evidence,
        integration_evidence_to_observation,
    )
    from backend.services.observation_fabric import (
        PromotionService,
        WorldObservationProjector,
    )

    db = Database()
    await ObservationStore(db).ensure_indexes()

    docs = integration_tool_result_to_integration_evidence(completed_job("zeek", "T1001"))
    first = integration_evidence_to_observation(docs[0])
    repeat = integration_evidence_to_observation(docs[0])

    first_decision = await PromotionService(db).evaluate(first)
    repeat_decision = await PromotionService(db).evaluate(repeat)

    await WorldObservationProjector(db).project(first, first_decision)
    await WorldObservationProjector(db).project(repeat, repeat_decision)

    assert first_decision.promote is True
    assert repeat_decision.promote is True
    assert first_decision.material_revision == repeat_decision.material_revision == 1
    assert await db.world_events.count_documents({"type": "observation_promoted"}) == 1

