"""Behavior gates for the canonical observation and durable promotion rail."""
import math
import asyncio
from datetime import datetime

import pytest

from backend.services.observation_fabric import (
    build_observation, canonical_json, evidence_digest,
)
from observation_db_helpers import Database


def observation(**changes):
    fields = dict(witness="suricata", source_kind="network_ids",
                  source_event_type="alert", source_event_id="eve-001",
                  observed_at="2026-10-08T12:00:00Z", payload={"severity": 2},
                  entity_refs=["ip:172.28.0.4"], reconciliation_scope="network_alert",
                  native_severity=2, native_confidence=None,
                  provenance="suricata_eve_alert")
    fields.update(changes)
    return build_observation(**fields)


def test_build_observation_preserves_source_identity_and_witness():
    obs = observation()
    assert obs.schema == "seraph.observation.v1"
    assert obs.witness == "suricata"
    assert obs.source_event_id == "eve-001"
    assert obs.entity_refs == ["ip:172.28.0.4"]
    assert obs.native_severity == 2
    assert obs.promotion_state == "pending"
    assert datetime.fromisoformat(obs.ingested_at).utcoffset().total_seconds() == 0


def test_observation_id_is_deterministic_for_same_source_identity():
    assert observation().observation_id == observation(payload={"severity": 1}).observation_id
    assert observation().observation_id != observation(source_event_id="eve-002").observation_id
    assert observation().observation_id != observation(witness="zeek").observation_id


def test_evidence_digest_is_order_independent_for_json_objects():
    assert evidence_digest({"a": 1, "b": [2]}) == evidence_digest({"b": [2], "a": 1})
    assert evidence_digest({"a": 1}) != evidence_digest({"a": 2})
    assert canonical_json({"b": 2, "a": 1}) == '{"a":1,"b":2}'


@pytest.mark.parametrize("value", [datetime.now(), {1: "key"}, (1, 2), {"a": math.nan}, {"a": math.inf}, {"a": object()}])
def test_canonical_json_rejects_non_json_safe_values(value):
    with pytest.raises((TypeError, ValueError)):
        canonical_json(value)


@pytest.mark.parametrize("value", [None, "", " "])
def test_observation_rejects_missing_source_identity(value):
    with pytest.raises(ValueError):
        observation(source_event_id=value)


@pytest.mark.asyncio
async def test_observation_store_claims_source_identity_once():
    from backend.services.observation_fabric import ObservationStore
    db = Database()
    store = ObservationStore(db)
    await store.ensure_indexes()
    assert await store.claim(observation()) is True
    doc = await store.get(observation().observation_id)
    assert doc["witness"] == "suricata"
    assert doc["promotion_state"] == "pending"


@pytest.mark.asyncio
async def test_observation_store_duplicate_claim_returns_false():
    from backend.services.observation_fabric import ObservationStore
    db = Database()
    await ObservationStore(db).ensure_indexes()
    assert await ObservationStore(db).claim(observation()) is True
    assert await ObservationStore(db).claim(observation()) is False
    assert await db.canonical_observations.count_documents({}) == 1


@pytest.mark.asyncio
async def test_ensure_indexes_declares_required_unique_indexes():
    from backend.services.observation_fabric import ObservationStore
    db = Database()
    await ObservationStore(db).ensure_indexes()
    indexes = await db.canonical_observations.index_information()
    assert indexes["uniq_observation_id"]["unique"] is True
    assert indexes["uniq_observation_source_identity"]["key"] == [("witness", 1), ("source_event_type", 1), ("source_event_id", 1)]
    for name, index in [("vns_flows", "uniq_suricata_flow_source_event_id"),
                        ("vns_dns_queries", "uniq_suricata_dns_source_event_id"),
                        ("suricata_alert_evidence", "uniq_suricata_alert_source_event_id")]:
        spec = (await db[name].index_information())[index]
        assert spec["unique"] is True
        assert spec["partialFilterExpression"] == {
            "witness": "suricata", "source_event_id": {"$type": "string"}}
    spec = (await db.world_events.index_information())["uniq_promoted_observation_id"]
    assert spec["partialFilterExpression"] == {"type": "observation_promoted"}
    assert spec["key"] == [("payload.observation_id", 1)]
    assert (await db.observation_material_state.index_information())["uniq_material_key"]["unique"]


@pytest.mark.asyncio
async def test_startup_reuses_phase4_suricata_indexes_without_replacing_them():
    from backend.services.observation_fabric import ObservationStore
    db = Database()
    for collection, index in [("vns_flows", "uniq_suricata_flow_source_event_id"),
                               ("vns_dns_queries", "uniq_suricata_dns_source_event_id"),
                               ("suricata_alert_evidence", "uniq_suricata_alert_source_event_id")]:
        await db[collection].create_index(
            [("source_event_id", 1)], name=index, unique=True,
            partialFilterExpression={"witness": "suricata", "source_event_id": {"$type": "string"}})
    await ObservationStore(db).ensure_indexes()
    await ObservationStore(db).ensure_indexes()


@pytest.mark.asyncio
async def test_suricata_index_preserves_legacy_unidentified_evidence():
    from backend.services.observation_fabric import ObservationStore
    from pymongo.errors import DuplicateKeyError
    db = Database()
    await ObservationStore(db).ensure_indexes()
    for collection in ("vns_flows", "vns_dns_queries", "suricata_alert_evidence"):
        await db[collection].insert_one({"witness": "suricata"})
        await db[collection].insert_one({"witness": "suricata"})
        await db[collection].insert_one({"witness": "suricata", "source_event_id": "source-001"})
        with pytest.raises(DuplicateKeyError):
            await db[collection].insert_one({"witness": "suricata", "source_event_id": "source-001"})


@pytest.mark.asyncio
async def test_concurrent_duplicate_claim_converges_to_one_observation():
    from backend.services.observation_fabric import ObservationStore
    db = Database()
    await ObservationStore(db).ensure_indexes()
    results = await asyncio.gather(*(ObservationStore(db).claim(observation()) for _ in range(20)))
    assert sum(results) == 1
    assert await db.canonical_observations.count_documents({}) == 1


def alert_observation(**changes):
    from test_suricata_observation_bridge import evidence
    from backend.services.observation_fabric import suricata_alert_to_observation
    return suricata_alert_to_observation(evidence(**changes))


@pytest.mark.asyncio
async def test_first_material_alert_promotes():
    from backend.services.observation_fabric import ObservationStore, PromotionService
    db = Database()
    await ObservationStore(db).ensure_indexes()
    decision = await PromotionService(db).evaluate(alert_observation())
    assert decision.promote is True
    assert decision.kind == "novel_material_observation"


@pytest.mark.asyncio
async def test_same_material_alert_with_new_source_event_is_retained_without_promotion():
    from backend.services.observation_fabric import ObservationStore, PromotionService
    db = Database()
    await ObservationStore(db).ensure_indexes()
    await PromotionService(db).evaluate(alert_observation())
    decision = await PromotionService(db).evaluate(alert_observation(source_event_id="eve-002", src_port=60001, timestamp="2026-10-08T13:00:00Z"))
    assert decision.promote is False
    assert decision.kind == "repeat_without_material_change"


@pytest.mark.asyncio
async def test_severity_change_promotes():
    from backend.services.observation_fabric import ObservationStore, PromotionService
    db = Database()
    await ObservationStore(db).ensure_indexes()
    await PromotionService(db).evaluate(alert_observation())
    decision = await PromotionService(db).evaluate(alert_observation(source_event_id="eve-002", severity=1))
    assert decision.promote is True
    assert decision.kind == "material_change"


@pytest.mark.asyncio
async def test_category_change_promotes():
    from backend.services.observation_fabric import ObservationStore, PromotionService
    db = Database()
    await ObservationStore(db).ensure_indexes()
    await PromotionService(db).evaluate(alert_observation())
    decision = await PromotionService(db).evaluate(alert_observation(source_event_id="eve-002", category="Changed native category"))
    assert decision.promote is True
    assert decision.kind == "material_change"


@pytest.mark.asyncio
async def test_concurrent_same_material_state_promotes_once():
    from backend.services.observation_fabric import ObservationStore, PromotionService
    db = Database()
    await ObservationStore(db).ensure_indexes()
    results = await asyncio.gather(*(PromotionService(db).evaluate(alert_observation(source_event_id=f"eve-{i}")) for i in range(20)))
    assert sum(result.promote for result in results) == 1
    assert await db.canonical_observations.count_documents({}) == 20


def test_direction_normalizes_service_without_ephemeral_port_or_invented_roles():
    from backend.services.observation_fabric import SuricataAlertPromotionPolicy
    policy = SuricataAlertPromotionPolicy()
    a = alert_observation()
    reverse = alert_observation(direction="to_client", src_ip="172.28.0.5", dst_ip="172.28.0.4", src_port=443, dst_port=60000)
    assert policy.material_key(a) == policy.material_key(reverse)
    assert policy.material_digest(a) == policy.material_digest(reverse)
    neutral = alert_observation(direction=None)
    assert "service_port" not in policy.material_key(neutral)
    assert policy.material_key(neutral) == policy.material_key(alert_observation(direction=None, src_ip="172.28.0.5", dst_ip="172.28.0.4"))


@pytest.mark.asyncio
async def test_promotion_decision_survives_death_after_material_state_update():
    from backend.services.observation_fabric import ObservationStore, PromotionService
    db = Database()
    await ObservationStore(db).ensure_indexes()
    obs = alert_observation()
    await ObservationStore(db).claim(obs)
    db.canonical_observations.failure = RuntimeError("process died before decision receipt")
    with pytest.raises(RuntimeError):
        await PromotionService(db).evaluate(obs)
    db.canonical_observations.failure = None
    decision = await PromotionService(db).evaluate(obs)
    assert decision.promote is True
    assert decision.kind == "novel_material_observation"
    assert (await PromotionService(db).evaluate(obs)) == decision


async def projection_inputs():
    from backend.services.observation_fabric import ObservationStore, PromotionService
    db = Database()
    await ObservationStore(db).ensure_indexes()
    obs = alert_observation()
    decision = await PromotionService(db).evaluate(obs)
    return db, obs, decision


@pytest.mark.asyncio
async def test_promoted_observation_creates_alert_entity_and_world_event():
    from backend.services.observation_fabric import WorldObservationProjector
    db, obs, decision = await projection_inputs()
    result = await WorldObservationProjector(db).project(obs, decision)
    assert result["projected"] is True
    entity = await db.world_entities.find_one({})
    assert entity["type"] == "alert"
    assert entity["attributes"]["observation_id"] == obs.observation_id
    assert entity["attributes"]["native_severity"] == 2
    assert entity["attributes"]["payload"]["signature"] == "Native signature"
    assert entity["attributes"]["payload"]["category"] == "Native category"
    assert "risk_score" not in entity["attributes"]
    assert "techniques" not in entity["attributes"]
    event = await db.world_events.find_one({})
    assert event["type"] == "observation_promoted"
    assert event["payload"]["schema"] == "seraph.observation.world.v1"
    assert event["payload"]["evidence_digest"] == obs.evidence_digest
    assert event["source"] == "observation_fabric"
    assert event["triune_triggered"] is True


@pytest.mark.asyncio
async def test_promoted_observation_carries_tvr_receipt_reference():
    from backend.services.observation_fabric import WorldObservationProjector
    db, obs, decision = await projection_inputs()
    await WorldObservationProjector(db).project(obs, decision)

    entity = await db.world_entities.find_one({})
    event = await db.world_events.find_one({})

    receipt = event["payload"]["tvr_receipt_ref"]
    assert receipt == entity["attributes"]["tvr_receipt_ref"]
    assert receipt["schema"] == "seraph.tvr.receipt_ref.v1"
    assert receipt["record_type"] == "technique_validation_record"
    assert receipt["receipt_kind"] == "observation_promotion"
    assert receipt["observation_id"] == obs.observation_id
    assert receipt["evidence_digest"] == obs.evidence_digest
    assert receipt["source"] == "observation_fabric"
    assert receipt["promotion_event_type"] == "observation_promoted"
    assert receipt["tvr_layer_targets"] == [
        "telemetry_evidence",
        "host_telemetry_evidence",
        "network_telemetry_evidence",
    ]


@pytest.mark.asyncio
async def test_retained_observation_creates_no_world_event():
    from backend.services.observation_fabric import PromotionService, WorldObservationProjector
    db, obs, decision = await projection_inputs()
    repeat = alert_observation(source_event_id="eve-002")
    retained = await PromotionService(db).evaluate(repeat)
    result = await WorldObservationProjector(db).project(repeat, retained)
    assert result["projected"] is False
    assert await db.world_events.count_documents({}) == 0
    assert await db.world_entities.count_documents({}) == 0


@pytest.mark.asyncio
async def test_projection_replay_keeps_one_world_event():
    from backend.services.observation_fabric import WorldObservationProjector
    db, obs, decision = await projection_inputs()
    await asyncio.gather(*(WorldObservationProjector(db).project(obs, decision) for _ in range(10)))
    assert await db.world_events.count_documents({}) == 1
    assert await db.world_entities.count_documents({}) == 1


@pytest.mark.asyncio
async def test_crash_after_entity_upsert_reconciles_to_one_world_event():
    from backend.services.observation_fabric import WorldObservationProjector
    db, obs, decision = await projection_inputs()
    db.world_events.failure = RuntimeError("process died after entity upsert")
    with pytest.raises(RuntimeError):
        await WorldObservationProjector(db).project(obs, decision)
    assert await db.world_entities.count_documents({}) == 1
    assert (await db.canonical_observations.find_one({}))["promotion_state"] == "pending"
    db.world_events.failure = None
    await WorldObservationProjector(db).project(obs, decision)
    await WorldObservationProjector(db).project(obs, decision)
    assert await db.world_events.count_documents({}) == 1


@pytest.mark.asyncio
async def test_world_event_persistence_failure_does_not_report_emitted():
    from backend.services.observation_fabric import WorldObservationProjector
    from test_suricata_observation_bridge import evidence
    db, obs, decision = await projection_inputs()
    await db.suricata_alert_evidence.insert_one(evidence(world_fanout_status="observed", observation_id=obs.observation_id))
    db.world_events.failure = RuntimeError("Mongo unavailable")
    with pytest.raises(RuntimeError):
        await WorldObservationProjector(db).project(obs, decision)
    assert (await db.suricata_alert_evidence.find_one({}))["world_fanout_status"] == "observed"
    assert await db.world_events.count_documents({}) == 0


@pytest.mark.asyncio
async def test_projection_triggers_triune_for_promoted_observation(monkeypatch):
    from backend.services.observation_fabric import WorldObservationProjector
    from backend.services import world_events

    calls = []

    class RecordingTriune:
        def __init__(self, db):
            self.db = db

        async def handle_world_change(self, **kwargs):
            calls.append(kwargs)
            return {"status": "ok"}

    monkeypatch.setattr(
        world_events, "_load_triune_orchestrator", lambda: RecordingTriune
    )
    db, obs, decision = await projection_inputs()
    result = await WorldObservationProjector(db).project(obs, decision)
    event = await db.world_events.find_one({})
    assert event["triune_triggered"] is True
    assert result["triune_triggered"] is True
    assert len(calls) == 1
    assert calls[0]["event_type"] == "observation_promoted"


@pytest.mark.asyncio
async def test_emit_world_event_strict_persistence_raises_on_insert_failure():
    from backend.services.world_events import emit_world_event
    db = Database()
    db.world_events.failure = RuntimeError("Mongo unavailable")
    with pytest.raises(RuntimeError, match="Mongo unavailable"):
        await emit_world_event(db, "test", trigger_triune=False, strict_persistence=True)
    # Legacy callers retain their best-effort contract.
    result = await emit_world_event(db, "test", trigger_triune=False)
    assert result["event"]["type"] == "test"


@pytest.mark.asyncio
async def test_strict_persistence_rejects_missing_database():
    from backend.services.world_events import emit_world_event
    with pytest.raises(RuntimeError):
        await emit_world_event(None, "test", trigger_triune=False, strict_persistence=True)


@pytest.mark.asyncio
async def test_passive_entity_upsert_avoids_collection_truthiness_and_risk_synthesis():
    from backend.services.world_model import WorldModelService, WorldEntity, EntityType
    from observation_db_helpers import Collection
    class MotorLikeCollection(Collection):
        def __bool__(self):
            raise NotImplementedError("Mongo collections cannot be truth-tested")
    db = Database()
    db.collections["world_entities"] = MotorLikeCollection(db.raw.world_entities)
    await WorldModelService(db).upsert_entity(WorldEntity(id="alert-test", type=EntityType.alert), recalculate_risk=False)
    assert (await db.world_entities.find_one({"id": "alert-test"}))["attributes"] == {}


@pytest.mark.asyncio
async def test_concurrent_same_observation_evaluation_cannot_poison_material_key():
    from backend.services.observation_fabric import ObservationStore, PromotionService
    db = Database()
    await ObservationStore(db).ensure_indexes()
    obs = alert_observation()
    await ObservationStore(db).claim(obs)
    stale = PromotionService(db)
    original_get = stale.store.get
    paused = asyncio.Event()
    resume = asyncio.Event()
    first = True
    async def pause_after_undecided_read(observation_id):
        nonlocal first
        doc = await original_get(observation_id)
        # First read is the existence check, the second is the decision read.
        if first:
            first = False
        elif not doc.get("promotion_decision") and not paused.is_set():
            paused.set()
            await resume.wait()
        return doc
    stale.store.get = pause_after_undecided_read
    task = asyncio.create_task(stale.evaluate(obs))
    await asyncio.wait_for(paused.wait(), timeout=2)
    winner = await PromotionService(db).evaluate(obs)
    resume.set()
    assert await task == winner
    next_decision = await PromotionService(db).evaluate(alert_observation(source_event_id="eve-002"))
    assert next_decision.kind == "repeat_without_material_change"


@pytest.mark.asyncio
async def test_old_projection_retry_cannot_overwrite_newer_material_revision():
    from backend.services.observation_fabric import PromotionService, WorldObservationProjector
    db, old, old_decision = await projection_inputs()
    db.world_events.failure = RuntimeError("old event persistence failed")
    with pytest.raises(RuntimeError):
        await WorldObservationProjector(db).project(old, old_decision)
    newer = alert_observation(source_event_id="eve-002", severity=1, timestamp="2026-10-08T13:00:00Z")
    newer_decision = await PromotionService(db).evaluate(newer)
    db.world_events.failure = None
    await WorldObservationProjector(db).project(newer, newer_decision)
    await WorldObservationProjector(db).project(old, old_decision)
    entity = await db.world_entities.find_one({})
    assert entity["attributes"]["native_severity"] == 1
    assert entity["attributes"]["observation_id"] == newer.observation_id
    assert await db.world_events.count_documents({}) == 2
