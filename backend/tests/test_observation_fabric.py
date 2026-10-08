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
        assert spec["partialFilterExpression"] == {"witness": "suricata"}
    spec = (await db.world_events.index_information())["uniq_promoted_observation_id"]
    assert spec["partialFilterExpression"] == {"type": "observation_promoted"}
    assert spec["key"] == [("payload.observation_id", 1)]
    assert (await db.observation_material_state.index_information())["uniq_material_key"]["unique"]


@pytest.mark.asyncio
async def test_concurrent_duplicate_claim_converges_to_one_observation():
    from backend.services.observation_fabric import ObservationStore
    db = Database()
    await ObservationStore(db).ensure_indexes()
    results = await asyncio.gather(*(ObservationStore(db).claim(observation()) for _ in range(20)))
    assert sum(results) == 1
    assert await db.canonical_observations.count_documents({}) == 1
