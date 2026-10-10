
import sys
import types

import pytest


def load_integrations_manager():
    if "threat_intel" not in sys.modules:
        module = types.ModuleType("threat_intel")
        module.threat_intel = object()
        sys.modules["threat_intel"] = module
    from backend import integrations_manager
    return integrations_manager


@pytest.mark.asyncio
async def test_unified_agent_local_status_runs_backend_runtime(monkeypatch):
    integrations_manager = load_integrations_manager()
    async def forbidden_agent_queue(**kwargs):
        pytest.fail("status/health for unified_agent_local must not queue integration_runtime to unified agent")
    monkeypatch.setattr(integrations_manager, "_queue_unified_agent_runtime", forbidden_agent_queue)

    job = await integrations_manager.run_runtime_tool(
        tool="zeek",
        params={"action": "status"},
        runtime_target="unified_agent_local",
        agent_id="agent-001",
        actor="test",
        governance_context={
            "approved": True,
            "decision_id": "test-decision",
            "queue_id": "test-queue",
        },
    )

    assert job["status"] == "completed"
    assert job["result"]["action"] == "status"
    result = job.get("result") or {}
    assert result.get("agent_command_status") is None
    assert result.get("runtime_target") != "unified_agent"


@pytest.mark.asyncio
async def test_unified_agent_runtime_non_status_still_queues_agent(monkeypatch):
    integrations_manager = load_integrations_manager()

    queued = []

    async def fake_queue(**kwargs):
        queued.append(kwargs)
        job_id = kwargs["job_id"]
        await integrations_manager._persist_job(
            job_id,
            status="queued_for_triune_approval",
            result={
                "runtime_target": "unified_agent",
                "agent_id": kwargs["agent_id"],
                "command_type": "integration_runtime",
            },
        )
        return integrations_manager._jobs[job_id]

    monkeypatch.setattr(integrations_manager, "_queue_unified_agent_runtime", fake_queue)

    job = await integrations_manager.run_runtime_tool(
        tool="zeek",
        params={"action": "collect"},
        runtime_target="unified_agent",
        agent_id="agent-001",
        actor="test",
        governance_context={
            "approved": True,
            "decision_id": "test-decision",
            "queue_id": "test-queue",
        },
    )

    assert job["status"] == "queued_for_triune_approval"
    assert queued[0]["tool"] == "zeek"
    assert queued[0]["agent_id"] == "agent-001"
