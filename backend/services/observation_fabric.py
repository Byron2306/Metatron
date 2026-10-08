"""Durable source observations, separated from world-state promotion authority."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any
from pymongo.errors import DuplicateKeyError


def canonical_json(value: Any) -> str:
    """Serialize JSON values strictly; never coerce evidence into strings."""
    def validate(item):
        if item is None or type(item) in (str, bool, int, float):
            return
        if type(item) is list:
            for child in item:
                validate(child)
        elif type(item) is dict:
            for key, child in item.items():
                if type(key) is not str:
                    raise TypeError("JSON object keys must be strings")
                validate(child)
        else:
            raise TypeError("Evidence contains a non-JSON value")
    validate(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def evidence_digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CanonicalObservation:
    schema: str
    observation_id: str
    witness: str
    source_kind: str
    source_event_type: str
    source_event_id: str
    observed_at: str
    ingested_at: str
    entity_refs: list[str]
    reconciliation_scope: str
    native_severity: Any
    native_confidence: Any
    provenance: Any
    evidence_digest: str
    payload: dict[str, Any]
    promotion_state: str = "pending"

    def to_document(self) -> dict[str, Any]:
        return asdict(self)


def build_observation(*, witness: str, source_kind: str, source_event_type: str,
                      source_event_id: str, observed_at: str, payload: dict,
                      entity_refs: list[str] | None = None,
                      reconciliation_scope: str = "network_alert",
                      native_severity: Any = None, native_confidence: Any = None,
                      provenance: Any = None) -> CanonicalObservation:
    for name, value in (("witness", witness), ("source_event_type", source_event_type),
                        ("source_event_id", source_event_id)):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Missing {name}")
    digest = evidence_digest(payload)
    identity = f"{witness}|{source_event_type}|{source_event_id}"
    return CanonicalObservation(
        schema="seraph.observation.v1",
        observation_id="obs-" + hashlib.sha256(identity.encode()).hexdigest()[:24],
        witness=witness, source_kind=source_kind, source_event_type=source_event_type,
        source_event_id=source_event_id, observed_at=observed_at,
        ingested_at=datetime.now(timezone.utc).isoformat(),
        entity_refs=list(entity_refs or []), reconciliation_scope=reconciliation_scope,
        native_severity=native_severity, native_confidence=native_confidence,
        provenance=provenance, evidence_digest=digest,
        payload=json.loads(canonical_json(payload)),
    )


class ObservationStore:
    def __init__(self, db):
        if db is None:
            raise ValueError("Observation fabric requires a durable database")
        self.db = db

    async def ensure_indexes(self) -> None:
        await self.db.canonical_observations.create_index(
            [("observation_id", 1)], unique=True, name="uniq_observation_id")
        await self.db.canonical_observations.create_index(
            [("witness", 1), ("source_event_type", 1), ("source_event_id", 1)],
            unique=True, name="uniq_observation_source_identity")
        await self.db.observation_material_state.create_index(
            [("material_key", 1)], unique=True, name="uniq_material_key")
        await self.db.world_events.create_index(
            [("payload.observation_id", 1)], unique=True,
            partialFilterExpression={"type": "observation_promoted"},
            name="uniq_promoted_observation_id")
        for collection, name in (
            ("vns_flows", "uniq_suricata_flow_source_event_id"),
            ("vns_dns_queries", "uniq_suricata_dns_source_event_id"),
            ("suricata_alert_evidence", "uniq_suricata_alert_source_event_id"),
        ):
            await self.db[collection].create_index(
                [("source_event_id", 1)], unique=True,
                partialFilterExpression={"witness": "suricata"}, name=name)

    async def claim(self, observation: CanonicalObservation) -> bool:
        try:
            result = await self.db.canonical_observations.update_one(
                {"observation_id": observation.observation_id},
                {"$setOnInsert": observation.to_document()}, upsert=True)
            return result.upserted_id is not None
        except DuplicateKeyError:
            # Only a verified existing identity is a duplicate; other errors propagate.
            if await self.get(observation.observation_id) is None:
                raise
            return False

    async def get(self, observation_id: str) -> dict | None:
        return await self.db.canonical_observations.find_one({"observation_id": observation_id})
