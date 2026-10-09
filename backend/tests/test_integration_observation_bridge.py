import pytest

from observation_db_helpers import Database
from backend.services.observation_fabric import ObservationStore


def integration_evidence(**overrides):
    doc = {
        "schema": "seraph.integration.evidence.v1",
        "source_kind": "integration_evidence",
        "integration_name": "evidence_bundle",
        "evidence_type": "agent_monitors",
        "technique_id": "T1059",
        "timestamp": "2026-10-09T06:50:00+00:00",
        "payload": {
            "monitor": "process_tree",
            "status": "observed",
            "coverage": ["process", "command_line"],
        },
        "world_fanout_status": "pending",
    }
    doc.update(overrides)
    return doc


def test_integration_evidence_maps_to_canonical_observation():
    from backend.services.integration_observation_fabric import (
        integration_evidence_to_observation,
    )

    obs = integration_evidence_to_observation(integration_evidence())

    assert obs.schema == "seraph.observation.v1"
    assert obs.witness == "integration_evidence"
    assert obs.source_kind == "integration_evidence"
    assert obs.source_event_type == "agent_monitors"
    assert obs.source_event_id == "evidence_bundle|agent_monitors|T1059|2026-10-09T06:50:00+00:00"
    assert obs.reconciliation_scope == "integration_evidence"
    assert obs.provenance == "evidence_bundle"
    assert obs.entity_refs == ["mitre:T1059"]
    assert obs.payload["payload"]["monitor"] == "process_tree"


@pytest.mark.asyncio
async def test_integration_bridge_claims_only_pending_evidence():
    from backend.services.integration_observation_fabric import IntegrationObservationBridge

    db = Database()
    await ObservationStore(db).ensure_indexes()

    await db.integration_evidence.insert_one(integration_evidence())
    await db.integration_evidence.insert_one(integration_evidence(
        technique_id="T1110",
        world_fanout_status="observed",
    ))

    result = await IntegrationObservationBridge(db).claim_pending()

    assert result == {"claimed": 1, "reconciled": 0, "failed": 0}
    assert await db.canonical_observations.count_documents({}) == 1

    source = await db.integration_evidence.find_one({"technique_id": "T1059"})
    assert source["world_fanout_status"] == "observed"
    assert source["observation_id"].startswith("obs-")


@pytest.mark.asyncio
async def test_integration_bridge_rejects_missing_technique_without_marking_observed():
    from backend.services.integration_observation_fabric import IntegrationObservationBridge

    db = Database()
    await ObservationStore(db).ensure_indexes()

    await db.integration_evidence.insert_one(integration_evidence(technique_id=""))

    result = await IntegrationObservationBridge(db).claim_pending()

    assert result["failed"] == 1
    assert await db.canonical_observations.count_documents({}) == 0

    source = await db.integration_evidence.find_one({})
    assert source["world_fanout_status"] == "pending"
    assert "observation_id" not in source
