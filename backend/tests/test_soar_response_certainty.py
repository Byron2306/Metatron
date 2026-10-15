import pytest

from observation_db_helpers import Database


def denied_response_execution():
    return {
        "id": "exec-response-001",
        "playbook_id": "response-certainty-test",
        "playbook_name": "Response certainty test",
        "trigger_event": {
            "trigger_type": "deception_token_access",
            "host_id": "203.0.113.77",
            "session_id": "case-001",
            "mitre_techniques": ["T1552"],
        },
        "status": "partial",
        "started_at": "2026-10-15T12:00:00+00:00",
        "completed_at": "2026-10-15T12:00:01+00:00",
        "semantic_response_state": "CONTAIN",
        "requested_response": {
            "schema": "seraph.soar.requested_response.v1",
            "semantic_state": "CONTAIN",
            "playbook_id": "response-certainty-test",
        },
        "orchestration_receipt": {
            "schema": "seraph.soar.orchestration_receipt.v1",
            "status": "partial",
            "steps_total": 2,
            "steps_denied": 2,
        },
        "actual_effect_receipt": {
            "schema": "seraph.soar.actual_effect_receipt.v1",
            "effect_verification": "denied",
            "effect_counts": {
                "attempted": 2,
                "applied": 0,
                "denied": 2,
                "queued": 0,
                "failed": 0,
                "verified": 0,
                "unverified": 0,
            },
            "requested_vs_actual": {
                "state": "denied",
                "requested_actions": ["feed_disinformation", "block_ip"],
                "applied_actions": [],
                "denied_actions": ["feed_disinformation", "block_ip"],
                "queued_actions": [],
                "failed_actions": [],
            },
            "effects": [
                {
                    "action": "feed_disinformation",
                    "outcome": "denied",
                    "authority": "mcp",
                    "reason": "Token not found",
                },
                {
                    "action": "block_ip",
                    "outcome": "denied",
                    "authority": "outbound_gate",
                    "reason": "notation validation failure",
                },
            ],
        },
    }


@pytest.mark.asyncio
async def test_denied_effects_make_execution_partial_and_persist_reasons(monkeypatch):
    from backend.soar_engine import (
        DefenseEscalationLevel,
        Playbook,
        PlaybookAction,
        PlaybookStep,
        PlaybookTrigger,
        SOAREngine,
    )

    db = Database()
    engine = SOAREngine()
    engine.playbooks["response-certainty-test"] = Playbook(
        id="response-certainty-test",
        name="Response certainty test",
        description="Exercise two governed response effects",
        trigger=PlaybookTrigger.DECEPTION_TOKEN_ACCESS,
        trigger_conditions={},
        steps=[
            PlaybookStep(action=PlaybookAction.FEED_DISINFORMATION),
            PlaybookStep(action=PlaybookAction.BLOCK_IP),
        ],
        escalation_level=DefenseEscalationLevel.CONTAIN,
        mitre_techniques=["T1552"],
    )

    async def deny_mcp(**kwargs):
        return {"status": "denied", "error": "Token not found"}

    async def deny_gate(**kwargs):
        return {"status": "denied", "message": "notation validation failure"}

    monkeypatch.setattr(engine, "_execute_via_mcp", deny_mcp)
    monkeypatch.setattr(engine, "_check_outbound_gate", deny_gate)

    execution = await engine.execute_playbook(
        "response-certainty-test",
        {
            "trigger_type": "deception_token_access",
            "host_id": "203.0.113.77",
            "session_id": "case-001",
        },
        db=db,
    )
    stored = await db.soar_executions.find_one({"id": execution.id})
    response_observation = await db.canonical_observations.find_one({
        "source_event_type": "soar_response_effect",
    })

    assert stored["status"] == "partial"
    assert stored["orchestration_receipt"]["steps_denied"] == 2
    assert stored["actual_effect_receipt"]["effect_verification"] == "denied"
    assert stored["actual_effect_receipt"]["effect_counts"]["denied"] == 2
    assert stored["actual_effect_receipt"]["requested_vs_actual"]["state"] == "denied"
    assert stored["actual_effect_receipt"]["effects"] == [
        {
            "step": 1,
            "action": "feed_disinformation",
            "orchestration_status": "denied",
            "reported_effect_status": "denied",
            "outcome": "denied",
            "verification": "not_applied",
            "authority": "mcp",
            "reason": "Token not found",
            "action_id": None,
            "queue_id": None,
        },
        {
            "step": 2,
            "action": "block_ip",
            "orchestration_status": "denied",
            "reported_effect_status": "denied",
            "outcome": "denied",
            "verification": "not_applied",
            "authority": "outbound_gate",
            "reason": "notation validation failure",
            "action_id": None,
            "queue_id": None,
        },
    ]
    assert response_observation["payload"]["payload"]["execution_id"] == execution.id
    assert stored["response_evidence_refs"][0]["observation_id"] == response_observation["observation_id"]


def test_soar_execution_maps_to_response_effect_evidence():
    from backend.services.integration_observation_fabric import (
        soar_execution_to_integration_evidence,
    )

    docs = soar_execution_to_integration_evidence(denied_response_execution())

    assert len(docs) == 1
    doc = docs[0]
    assert doc["integration_name"] == "soar"
    assert doc["evidence_type"] == "soar_response_effect"
    assert doc["technique_id"] == "T1552"
    assert doc["source_event_id"] == "soar|soar_response_effect|T1552|exec-response-001"
    assert doc["payload"]["response_outcome"] == "denied"
    assert doc["payload"]["actual_effect_receipt"]["effect_counts"]["denied"] == 2


@pytest.mark.asyncio
async def test_soar_execution_ingests_claims_and_summarizes_in_evidence_graph():
    from backend.services.evidence_graph import build_technique_evidence_graph
    from backend.services.integration_observation_fabric import IntegrationObservationBridge
    from backend.services.observation_fabric import ObservationStore

    db = Database()
    await ObservationStore(db).ensure_indexes()
    await db.soar_executions.insert_one(denied_response_execution())

    result = await IntegrationObservationBridge(db).ingest_soar_executions()
    observation = await db.canonical_observations.find_one({
        "source_event_type": "soar_response_effect",
    })
    graph = await build_technique_evidence_graph(db, "T1552")

    assert result == {
        "ingested": True,
        "loaded": 1,
        "inserted": 1,
        "duplicates": 0,
        "claimed": 1,
        "reconciled": 0,
        "failed": 0,
    }
    assert observation["provenance"] == "soar"
    assert observation["entity_refs"] == ["mitre:T1552"]
    assert graph["sources"]["soar"][0]["observation_id"] == observation["observation_id"]
    assert graph["response_effects"] == {
        "attempted": 2,
        "applied": 0,
        "denied": 2,
        "queued": 0,
        "failed": 0,
        "verified": 0,
        "unverified": 0,
        "outcomes": ["denied"],
    }


def test_response_effect_projection_metadata_preserves_delta_receipt():
    from backend.services.integration_observation_fabric import (
        integration_evidence_to_observation,
        soar_execution_to_integration_evidence,
    )
    from backend.services.observation_fabric import integration_projection_metadata

    evidence = soar_execution_to_integration_evidence(denied_response_execution())[0]
    observation = integration_evidence_to_observation(evidence)

    metadata = integration_projection_metadata(observation)

    assert metadata["response_effect_receipt"]["schema"] == "seraph.response.effect_projection.v1"
    assert metadata["response_effect_receipt"]["execution_id"] == "exec-response-001"
    assert metadata["response_effect_receipt"]["response_outcome"] == "denied"
    assert metadata["response_effect_receipt"]["requested_vs_actual"]["state"] == "denied"


@pytest.mark.asyncio
async def test_honeytoken_trigger_automatically_hands_soar_receipt_to_observation_rail(monkeypatch):
    from backend.services.integration_observation_fabric import IntegrationObservationBridge
    from backend.services.observation_fabric import ObservationStore
    from backend.soar_engine import SOAREngine

    async def deterministic_trigger(self, event, db=None):
        execution = denied_response_execution()
        execution["trigger_event"] = {
            **execution["trigger_event"],
            "observation_id": event["observation_id"],
            "source_event_id": event["source_event_id"],
        }
        await db.soar_executions.insert_one(execution)

        class Result:
            id = execution["id"]

        return [Result()]

    monkeypatch.setattr(SOAREngine, "trigger_playbooks", deterministic_trigger)

    db = Database()
    await ObservationStore(db).ensure_indexes()
    await db.honey_token_accesses.insert_one({
        "id": "hta-response-001",
        "token_id": "ht-prod-aws-001",
        "accessed_at": "2026-10-15T12:00:00+00:00",
        "source_ip": "203.0.113.77",
        "severity": "critical",
    })

    result = await IntegrationObservationBridge(db).ingest_honeytoken_accesses(
        trigger_soar=True,
    )

    response = await db.canonical_observations.find_one({
        "source_event_type": "soar_response_effect",
    })
    execution = await db.soar_executions.find_one({"id": "exec-response-001"})

    assert result["soar_evidence_claimed"] == 1
    assert result["soar_evidence_linked"] == 1
    assert response["payload"]["payload"]["response_outcome"] == "denied"
    assert execution["response_evidence_refs"] == [{
        "technique_id": "T1552",
        "source_event_id": "soar|soar_response_effect|T1552|exec-response-001",
        "observation_id": response["observation_id"],
    }]
