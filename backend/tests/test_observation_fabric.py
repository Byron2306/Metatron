"""Behavior gates for the canonical observation and durable promotion rail."""
import math
from datetime import datetime

import pytest

from backend.services.observation_fabric import (
    build_observation, canonical_json, evidence_digest,
)


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
