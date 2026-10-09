"""Unified Agent endpoint evidence gates for the canonical observation rail."""
import pytest

from observation_db_helpers import Database
from backend.services.observation_fabric import ObservationStore


def endpoint_evidence(**changes):
    doc = {
        "schema": "seraph.endpoint.evidence.v1",
        "source_kind": "unified_agent",
        "agent_id": "agent-001",
        "node_id": "node-001",
        "hostname": "debian",
        "platform": "linux",
        "timestamp": "2026-10-09T05:40:00+00:00",
        "threat_count": 1,
        "network_connections": 12,
        "cpu_usage": 7.5,
        "memory_usage": 42.0,
        "disk_usage": 55.0,
        "monitor_fleet_total": 2,
        "monitor_fleet_summary": {
            "process_tree": {"kind": "process", "enabled": True, "state": "active"},
            "dns": {"kind": "network", "enabled": True, "state": "active"},
        },
        "world_fanout_status": "pending",
    }
    doc.update(changes)
    return doc


def test_unified_agent_endpoint_evidence_maps_to_canonical_observation():
    from backend.services.agent_observation_fabric import (
        unified_agent_endpoint_evidence_to_observation,
    )

    obs = unified_agent_endpoint_evidence_to_observation(endpoint_evidence())

    assert obs.schema == "seraph.observation.v1"
    assert obs.witness == "unified_agent"
    assert obs.source_kind == "endpoint_agent"
    assert obs.source_event_type == "endpoint_evidence"
    assert obs.source_event_id == "agent-001|2026-10-09T05:40:00+00:00"
    assert obs.entity_refs == ["agent:agent-001", "node:node-001", "host:debian"]
    assert obs.reconciliation_scope == "endpoint_evidence"
    assert obs.native_severity == 1
    assert obs.provenance == "unified_agent_heartbeat"
    assert obs.payload["schema"] == "seraph.endpoint.evidence.v1"
    assert obs.payload["monitor_fleet_total"] == 2
    assert "world_fanout_status" not in obs.payload
    assert "observation_id" not in obs.payload


@pytest.mark.asyncio
async def test_unified_agent_bridge_claims_only_pending_endpoint_evidence():
    from backend.services.agent_observation_fabric import AgentEndpointObservationBridge

    db = Database()
    await ObservationStore(db).ensure_indexes()
    await db.agent_endpoint_evidence.insert_one(endpoint_evidence())
    await db.agent_endpoint_evidence.insert_one(endpoint_evidence(
        agent_id="old-agent",
        world_fanout_status="observed",
    ))

    result = await AgentEndpointObservationBridge(db).claim_pending()

    assert result["claimed"] == 1
    assert result["failed"] == 0
    assert await db.canonical_observations.count_documents({}) == 1
    doc = await db.agent_endpoint_evidence.find_one({"agent_id": "agent-001"})
    assert doc["world_fanout_status"] == "observed"
    assert doc["observation_id"].startswith("obs-")


@pytest.mark.asyncio
async def test_unified_agent_bridge_rejects_missing_agent_id_without_marking_observed():
    from backend.services.agent_observation_fabric import AgentEndpointObservationBridge

    db = Database()
    await db.agent_endpoint_evidence.insert_one(endpoint_evidence(agent_id=""))

    result = await AgentEndpointObservationBridge(db).claim_pending()

    assert result["failed"] == 1
    assert await db.canonical_observations.count_documents({}) == 0
    doc = await db.agent_endpoint_evidence.find_one({})
    assert doc["world_fanout_status"] == "pending"


@pytest.mark.asyncio
async def test_unified_agent_heartbeat_endpoint_change_claims_canonical_observation(monkeypatch):
    from backend.routers import unified_agent
    from backend.routers.unified_agent import AgentHeartbeatModel

    db = Database()
    await ObservationStore(db).ensure_indexes()

    await db.unified_agents.insert_one({
        "agent_id": "agent-001",
        "node_id": "node-001",
        "hostname": "debian",
        "platform": "linux",
        "status": "online",
        "threat_count": 0,
        "network_connections": 0,
        "monitor_fleet_summary": {},
        "config": {},
    })

    monkeypatch.setattr(unified_agent, "db", db)
    monkeypatch.setattr(unified_agent, "_process_agent_alert", lambda *args, **kwargs: None)
    monkeypatch.setattr(unified_agent, "_hunt_telemetry", lambda *args, **kwargs: None)

    class DummyWS:
        def get_queued_commands(self, agent_id):
            return []

    monkeypatch.setattr(unified_agent, "agent_ws_manager", DummyWS())

    heartbeat = AgentHeartbeatModel(
        agent_id="agent-001",
        status="online",
        cpu_usage=10.0,
        memory_usage=20.0,
        disk_usage=30.0,
        threat_count=1,
        network_connections=5,
        node_id="node-001",
        monitor_fleet={
            "process_tree": {"kind": "process", "enabled": True, "state": "active"},
        },
    )

    result = await unified_agent.agent_heartbeat(
        "agent-001",
        heartbeat,
        request=None,
        auth={"type": "test", "ip": "127.0.0.1", "agent_id": "agent-001"},
    )

    assert result["status"] == "ok"
    assert await db.agent_endpoint_evidence.count_documents({}) == 1

    evidence = await db.agent_endpoint_evidence.find_one({})
    assert evidence["world_fanout_status"] == "observed"
    assert evidence["observation_id"].startswith("obs-")

    obs = await db.canonical_observations.find_one({})
    assert obs["witness"] == "unified_agent"
    assert obs["source_kind"] == "endpoint_agent"
    assert obs["source_event_type"] == "endpoint_evidence"
    assert obs["reconciliation_scope"] == "endpoint_evidence"
    assert obs["entity_refs"] == ["agent:agent-001", "node:node-001", "host:debian"]


@pytest.mark.asyncio
async def test_endpoint_observation_promotes_material_agent_state_change():
    from backend.services.agent_observation_fabric import (
        unified_agent_endpoint_evidence_to_observation,
    )
    from backend.services.observation_fabric import PromotionService

    db = Database()
    await ObservationStore(db).ensure_indexes()

    obs = unified_agent_endpoint_evidence_to_observation(endpoint_evidence())
    decision = await PromotionService(db).evaluate(obs)

    assert decision.promote is True
    assert decision.kind == "novel_material_observation"
    assert decision.material_key.startswith("endpoint_evidence|")
    assert "agent-001" in decision.material_key

    stored = await db.canonical_observations.find_one({"observation_id": obs.observation_id})
    assert stored["promotion_decision"]["promote"] is True


@pytest.mark.asyncio
async def test_endpoint_observation_repeat_without_material_change_is_retained():
    from backend.services.agent_observation_fabric import (
        unified_agent_endpoint_evidence_to_observation,
    )
    from backend.services.observation_fabric import PromotionService

    db = Database()
    await ObservationStore(db).ensure_indexes()

    first = unified_agent_endpoint_evidence_to_observation(endpoint_evidence())
    repeat = unified_agent_endpoint_evidence_to_observation(endpoint_evidence(
        timestamp="2026-10-09T05:41:00+00:00",
    ))

    first_decision = await PromotionService(db).evaluate(first)
    repeat_decision = await PromotionService(db).evaluate(repeat)

    assert first_decision.promote is True
    assert repeat_decision.promote is False
    assert repeat_decision.kind == "repeat_without_material_change"
    assert repeat_decision.material_key == first_decision.material_key


@pytest.mark.asyncio
async def test_endpoint_observation_changed_material_promotes_revision_two():
    from backend.services.agent_observation_fabric import (
        unified_agent_endpoint_evidence_to_observation,
    )
    from backend.services.observation_fabric import PromotionService

    db = Database()
    await ObservationStore(db).ensure_indexes()

    first = unified_agent_endpoint_evidence_to_observation(endpoint_evidence())
    changed = unified_agent_endpoint_evidence_to_observation(endpoint_evidence(
        timestamp="2026-10-09T05:42:00+00:00",
        threat_count=2,
        network_connections=99,
    ))

    first_decision = await PromotionService(db).evaluate(first)
    changed_decision = await PromotionService(db).evaluate(changed)

    assert first_decision.promote is True
    assert changed_decision.promote is True
    assert changed_decision.kind == "material_change"
    assert changed_decision.material_key == first_decision.material_key
    assert changed_decision.material_revision == 2


@pytest.mark.asyncio
async def test_unified_agent_heartbeat_endpoint_change_projects_promoted_observation(monkeypatch):
    from backend.routers import unified_agent
    from backend.routers.unified_agent import AgentHeartbeatModel

    db = Database()
    await ObservationStore(db).ensure_indexes()

    await db.unified_agents.insert_one({
        "agent_id": "agent-001",
        "node_id": "node-001",
        "hostname": "debian",
        "platform": "linux",
        "status": "online",
        "threat_count": 0,
        "network_connections": 0,
        "monitor_fleet_summary": {},
        "config": {},
    })

    monkeypatch.setattr(unified_agent, "db", db)
    monkeypatch.setattr(unified_agent, "_process_agent_alert", lambda *args, **kwargs: None)
    monkeypatch.setattr(unified_agent, "_hunt_telemetry", lambda *args, **kwargs: None)

    class DummyWS:
        def get_queued_commands(self, agent_id):
            return []

    monkeypatch.setattr(unified_agent, "agent_ws_manager", DummyWS())

    heartbeat = AgentHeartbeatModel(
        agent_id="agent-001",
        status="online",
        cpu_usage=10.0,
        memory_usage=20.0,
        disk_usage=30.0,
        threat_count=1,
        network_connections=5,
        node_id="node-001",
        monitor_fleet={
            "process_tree": {"kind": "process", "enabled": True, "state": "active"},
        },
    )

    await unified_agent.agent_heartbeat(
        "agent-001",
        heartbeat,
        request=None,
        auth={"type": "test", "ip": "127.0.0.1", "agent_id": "agent-001"},
    )

    obs = await db.canonical_observations.find_one({"witness": "unified_agent"})
    assert obs["promotion_state"] == "promoted"

    event = await db.world_events.find_one({"type": "observation_promoted"})
    assert event["payload"]["tvr_receipt_ref"]["witness"] == "unified_agent"
    assert event["payload"]["tvr_receipt_ref"]["source_event_type"] == "endpoint_evidence"
    assert event["triune_triggered"] is True

    entity = await db.world_entities.find_one({})
    assert entity["type"] == "endpoint"
    assert entity["id"].startswith("endpoint-")
    assert entity["attributes"]["tvr_receipt_ref"] == event["payload"]["tvr_receipt_ref"]


@pytest.mark.asyncio
async def test_unified_agent_repeat_endpoint_material_does_not_duplicate_world_event(monkeypatch):
    from backend.routers import unified_agent
    from backend.routers.unified_agent import AgentHeartbeatModel

    db = Database()
    await ObservationStore(db).ensure_indexes()

    await db.unified_agents.insert_one({
        "agent_id": "agent-001",
        "node_id": "node-001",
        "hostname": "debian",
        "platform": "linux",
        "status": "online",
        "threat_count": 0,
        "network_connections": 0,
        "monitor_fleet_summary": {},
        "config": {},
    })

    monkeypatch.setattr(unified_agent, "db", db)
    monkeypatch.setattr(unified_agent, "_process_agent_alert", lambda *args, **kwargs: None)
    monkeypatch.setattr(unified_agent, "_hunt_telemetry", lambda *args, **kwargs: None)

    class DummyWS:
        def get_queued_commands(self, agent_id):
            return []

    monkeypatch.setattr(unified_agent, "agent_ws_manager", DummyWS())

    heartbeat = AgentHeartbeatModel(
        agent_id="agent-001",
        status="online",
        cpu_usage=10.0,
        memory_usage=20.0,
        disk_usage=30.0,
        threat_count=1,
        network_connections=5,
        node_id="node-001",
        monitor_fleet={
            "process_tree": {"kind": "process", "enabled": True, "state": "active"},
        },
    )

    await unified_agent.agent_heartbeat(
        "agent-001",
        heartbeat,
        request=None,
        auth={"type": "test", "ip": "127.0.0.1", "agent_id": "agent-001"},
    )

    await db.unified_agents.update_one(
        {"agent_id": "agent-001"},
        {"$set": {
            "threat_count": 0,
            "network_connections": 0,
            "monitor_fleet_summary": {},
        }},
    )

    await unified_agent.agent_heartbeat(
        "agent-001",
        heartbeat,
        request=None,
        auth={"type": "test", "ip": "127.0.0.1", "agent_id": "agent-001"},
    )

    assert await db.agent_endpoint_evidence.count_documents({}) == 2
    assert await db.world_events.count_documents({"type": "observation_promoted"}) == 1
    assert await db.world_entities.count_documents({}) == 1

    states = await db.canonical_observations.find({}, {"_id": 0, "promotion_state": 1}).to_list(10)
    assert sorted(row["promotion_state"] for row in states) == [
        "promoted",
        "retained_without_promotion",
    ]
