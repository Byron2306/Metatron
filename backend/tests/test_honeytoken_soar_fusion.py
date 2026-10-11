import pytest

from observation_db_helpers import Database


def honeytoken_access():
    return {
        "id": "hta-001",
        "token_id": "ht-prod-aws-001",
        "token_name": "AWS Production Key",
        "token_type": "aws_key",
        "accessed_at": "2026-10-11T14:20:00+00:00",
        "source_ip": "203.0.113.77",
        "user_agent": "curl/8.0",
        "request_path": "/api/honey-tokens/check",
        "request_method": "POST",
        "headers": {"user-agent": "curl/8.0"},
        "severity": "critical",
        "deception_case_id": "deception-case-001",
        "deception_event_id": "deception-event-001",
    }


def test_honeytoken_access_maps_to_attack_integration_evidence():
    from backend.services.integration_observation_fabric import (
        honeytoken_access_to_integration_evidence,
    )

    doc = honeytoken_access_to_integration_evidence(honeytoken_access())

    assert doc["schema"] == "seraph.integration.evidence.v1"
    assert doc["integration_name"] == "honeytoken"
    assert doc["evidence_type"] == "honey_token_access"
    assert doc["technique_id"] == "T1552"
    assert doc["source_event_id"] == "honeytoken|honey_token_access|T1552|hta-001"
    assert doc["payload"]["token_id"] == "ht-prod-aws-001"
    assert doc["payload"]["deception_case_id"] == "deception-case-001"
    assert doc["world_fanout_status"] == "pending"


def test_honeytoken_status_without_access_id_is_not_evidence():
    from backend.services.integration_observation_fabric import (
        honeytoken_access_to_integration_evidence,
    )

    assert honeytoken_access_to_integration_evidence({"status": "healthy"}) is None


@pytest.mark.asyncio
async def test_honeytoken_access_ingest_claims_observation_and_triggers_soar():
    from backend.services.integration_observation_fabric import IntegrationObservationBridge
    from backend.services.observation_fabric import ObservationStore

    db = Database()
    await ObservationStore(db).ensure_indexes()

    await db.honey_token_accesses.insert_one(honeytoken_access())

    result = await IntegrationObservationBridge(db).ingest_honeytoken_accesses(
        trigger_soar=True,
    )

    source = await db.honey_token_accesses.find_one({"id": "hta-001"})
    obs = await db.canonical_observations.find_one({
        "source_event_type": "honey_token_access",
    })
    execution = await db.soar_executions.find_one({
        "playbook_id": "ai_decoy_hit_01",
    })

    assert result["inserted"] == 1
    assert result["claimed"] == 1
    assert result["soar_triggered"] >= 1
    assert source["world_fanout_status"] == "observed"
    assert source["observation_id"] == obs["observation_id"]
    assert obs["entity_refs"] == ["mitre:T1552"]
    assert obs["payload"]["payload"]["source_collection"] == "honey_token_accesses"
    assert execution["semantic_response_state"] == "OBSERVE"
    assert execution["requested_response"]["trigger_type"] == "deception_token_access"
    assert execution["trigger_event"]["observation_id"] == obs["observation_id"]
