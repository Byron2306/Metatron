import pytest

from observation_db_helpers import Database


def autonomous_recon_event():
    return {
        "trigger_type": "autonomous_recon",
        "host_id": "host-001",
        "session_id": "session-001",
        "machine_likelihood": "high",
        "intents": "recon",
        "burstiness": "high",
        "source_ip": "203.0.113.77",
    }


@pytest.mark.asyncio
async def test_ai_recon_degrade_execution_persists_semantic_response_receipts():
    from backend.soar_engine import SOAREngine

    db = Database()
    engine = SOAREngine()

    execution = await engine.execute_playbook(
        "ai_recon_degrade_01",
        autonomous_recon_event(),
        db=db,
    )

    stored = await db.soar_executions.find_one({"id": execution.id})

    assert stored is not None
    assert stored["id"] == execution.id
    assert stored["playbook_id"] == "ai_recon_degrade_01"
    assert stored["status"] == "completed"
    assert stored["semantic_response_state"] == "DEGRADE"
    assert stored["requested_response"] == {
        "schema": "seraph.soar.requested_response.v1",
        "semantic_state": "DEGRADE",
        "escalation_level": "degrade",
        "playbook_id": "ai_recon_degrade_01",
        "trigger_type": "autonomous_recon",
        "host_id": "host-001",
        "session_id": "session-001",
    }
    assert stored["orchestration_receipt"]["schema"] == "seraph.soar.orchestration_receipt.v1"
    assert stored["orchestration_receipt"]["status"] == "completed"
    assert stored["orchestration_receipt"]["steps_total"] == 7
    assert stored["orchestration_receipt"]["steps_completed"] == 7
    assert stored["actual_effect_receipt"]["schema"] == "seraph.soar.actual_effect_receipt.v1"
    assert stored["actual_effect_receipt"]["effect_verification"] == "not_verified"
    assert stored["actual_effect_receipt"]["requires_external_confirmation"] is True
    assert "throttle_cli" in stored["actual_effect_receipt"]["reported_step_actions"]
    assert "inject_latency" in stored["actual_effect_receipt"]["reported_step_actions"]


@pytest.mark.asyncio
async def test_trigger_playbooks_persists_matching_ai_recon_execution():
    from backend.soar_engine import SOAREngine

    db = Database()
    engine = SOAREngine()

    executions = await engine.trigger_playbooks(autonomous_recon_event(), db=db)
    stored = await db.soar_executions.find_one({"playbook_id": "ai_recon_degrade_01"})

    assert len(executions) == 1
    assert stored["semantic_response_state"] == "DEGRADE"
    assert stored["requested_response"]["semantic_state"] == "DEGRADE"
