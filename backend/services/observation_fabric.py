"""Durable source observations, separated from world-state promotion authority."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import logging
from typing import Any
from pymongo.errors import DuplicateKeyError

logger = logging.getLogger(__name__)


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
        await self.db.world_entities.create_index(
            [("id", 1)], unique=True, name="uniq_observation_alert_entity_id",
            partialFilterExpression={"type": "alert", "attributes.schema": "seraph.observation.world.v1"})
        for collection, name in (
            ("vns_flows", "uniq_suricata_flow_source_event_id"),
            ("vns_dns_queries", "uniq_suricata_dns_source_event_id"),
            ("suricata_alert_evidence", "uniq_suricata_alert_source_event_id"),
        ):
            await self.db[collection].create_index(
                [("source_event_id", 1)], unique=True,
                partialFilterExpression={
                    "witness": "suricata", "source_event_id": {"$type": "string"}},
                name=name)

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


def suricata_alert_to_observation(evidence: dict) -> CanonicalObservation:
    if evidence.get("witness") != "suricata" or evidence.get("source_event_type") != "alert":
        raise ValueError("Expected source-native Suricata alert evidence")
    # Mongo identity and mutable delivery bookkeeping are not source evidence.
    payload = {key: value for key, value in evidence.items()
               if key not in {"_id", "world_fanout_status", "observation_id"}}
    return build_observation(
        witness="suricata", source_kind="network_ids", source_event_type="alert",
        source_event_id=evidence.get("source_event_id"),
        observed_at=evidence.get("timestamp"), payload=payload,
        entity_refs=list(dict.fromkeys(f"ip:{evidence[key]}" for key in ("src_ip", "dst_ip") if evidence.get(key))),
        reconciliation_scope="network_alert", native_severity=evidence.get("severity"),
        native_confidence=evidence.get("confidence"), provenance=evidence.get("provenance"),
    )


class SuricataObservationBridge:
    def __init__(self, db):
        self.db = db
        self.store = ObservationStore(db)

    async def claim_pending(self, limit: int = 250) -> dict:
        if limit < 1:
            raise ValueError("limit must be positive")
        result = {"claimed": 0, "reconciled": 0, "failed": 0}
        docs = await self.db.suricata_alert_evidence.find(
            {"witness": "suricata", "world_fanout_status": "pending"}
        ).limit(limit).to_list(length=limit)
        for evidence in docs:
            try:
                observation = suricata_alert_to_observation(evidence)
                new = await self.store.claim(observation)
                status = "observed" if new else "reconciled"
                await self.db.suricata_alert_evidence.update_one(
                    {"_id": evidence["_id"], "world_fanout_status": "pending"},
                    {"$set": {"world_fanout_status": status,
                              "observation_id": observation.observation_id}})
                result["claimed" if new else "reconciled"] += 1
            except Exception:
                logger.exception("Suricata observation claim failed; evidence remains retryable")
                result["failed"] += 1
        return result

    async def drain(self, limit: int = 250) -> dict:
        result = await self.claim_pending(limit=limit)
        result.update(promoted=0, retained_without_promotion=0, projected=0, triune_triggered=False)
        # The canonical pending queue includes claims whose source was already
        # acknowledged before a projection failure or backend death.
        docs = await self.db.canonical_observations.find({
            "witness": "suricata", "source_event_type": "alert", "promotion_state": "pending"
        }).limit(limit).to_list(length=limit)
        for doc in docs:
            try:
                observation = CanonicalObservation(**{
                    field: doc[field] for field in CanonicalObservation.__dataclass_fields__})
                decision = await PromotionService(self.db).evaluate(observation)
                projection = await WorldObservationProjector(self.db).project(observation, decision)
                result["promoted" if decision.promote else "retained_without_promotion"] += 1
                result["projected"] += int(projection["projected"])
                result["triune_triggered"] = result["triune_triggered"] or bool(projection.get("triune_triggered"))
            except Exception:
                logger.exception("Observation promotion failed; canonical claim remains retryable")
                result["failed"] += 1
        return result


@dataclass(frozen=True)
class PromotionDecision:
    kind: str
    promote: bool
    material_key: str
    material_digest: str
    material_revision: int


class SuricataAlertPromotionPolicy:
    @staticmethod
    def service_context(observation: CanonicalObservation) -> dict:
        p = observation.payload
        direction = p.get("direction")
        if direction in ("to_server", "to_client"):
            initiator, service = ("src", "dst") if direction == "to_server" else ("dst", "src")
            return {"initiator_ip": p.get(f"{initiator}_ip"),
                    "service_ip": p.get(f"{service}_ip"),
                    "service_port": p.get(f"{service}_port")}
        return {"neutral_endpoints": sorted([p.get("src_ip") or "", p.get("dst_ip") or ""])}

    def material_key(self, observation: CanonicalObservation) -> str:
        if observation.witness != "suricata" or observation.source_event_type != "alert":
            raise ValueError("Suricata policy requires a Suricata alert")
        return "network_alert|" + canonical_json({
            "signature_id": observation.payload.get("signature_id"),
            "protocol": observation.payload.get("protocol"),
            **self.service_context(observation),
        })

    def material_digest(self, observation: CanonicalObservation) -> str:
        p = observation.payload
        return evidence_digest({
            **self.service_context(observation),
            **{key: p.get(key) for key in ("action", "category", "severity", "signature", "metadata", "protocol", "interface")},
        })


class EndpointEvidencePromotionPolicy:
    def material_key(self, observation: CanonicalObservation) -> str:
        if observation.witness != "unified_agent" or observation.source_event_type != "endpoint_evidence":
            raise ValueError("Endpoint policy requires Unified Agent endpoint evidence")
        return "endpoint_evidence|" + canonical_json({
            "agent_id": observation.payload.get("agent_id"),
            "node_id": observation.payload.get("node_id"),
            "hostname": observation.payload.get("hostname"),
            "platform": observation.payload.get("platform"),
        })

    def material_digest(self, observation: CanonicalObservation) -> str:
        p = observation.payload
        return evidence_digest({
            "threat_count": p.get("threat_count"),
            "network_connections": p.get("network_connections"),
            "monitor_fleet_total": p.get("monitor_fleet_total"),
            "monitor_fleet_summary": p.get("monitor_fleet_summary") or {},
        })


class PromotionService:
    """CAS material state with a recoverable receipt in the same Mongo document.

    The pending receipt closes the crash window between changing material state
    and recording the observation's decision. Any evaluator can finish it before
    advancing that key. No leases, process-local locks or RAM truth are required.
    """
    def __init__(self, db):
        self.db = db
        self.store = ObservationStore(db)
        self.policies = [
            SuricataAlertPromotionPolicy(),
            EndpointEvidencePromotionPolicy(),
        ]

    def _policy_for(self, observation: CanonicalObservation):
        if observation.witness == "suricata" and observation.source_event_type == "alert":
            return self.policies[0]
        if observation.witness == "unified_agent" and observation.source_event_type == "endpoint_evidence":
            return self.policies[1]
        raise ValueError(
            f"Unsupported observation promotion source: "
            f"{observation.witness}/{observation.source_event_type}"
        )

    async def _settle_receipt(self, state):
        receipt = state.get("pending_decision")
        if not receipt:
            return
        result = await self.db.canonical_observations.update_one(
            {"observation_id": receipt["observation_id"], "promotion_decision": {"$exists": False}},
            {"$set": {"promotion_decision": receipt["decision"]}})
        if not result.matched_count:
            owner = await self.store.get(receipt["observation_id"])
            if owner is None or owner.get("promotion_decision") != receipt["decision"]:
                raise RuntimeError("Material decision has no matching observation receipt")
        await self.db.observation_material_state.update_one(
            {"material_key": state["material_key"], "revision": state["revision"],
             "pending_decision.observation_id": receipt["observation_id"]},
            {"$unset": {"pending_decision": ""}})

    async def evaluate(self, observation: CanonicalObservation) -> PromotionDecision:
        policy = self._policy_for(observation)
        key = policy.material_key(observation)
        digest = policy.material_digest(observation)
        if await self.store.get(observation.observation_id) is None:
            await self.store.claim(observation)
        while True:
            # Read the CAS version BEFORE the observation decision. A stale
            # undecided read can then never advance a version another evaluator
            # used to settle this observation in the meantime.
            state = await self.db.observation_material_state.find_one({"material_key": key})
            owner = await self.store.get(observation.observation_id)
            if owner.get("promotion_decision"):
                return PromotionDecision(**owner["promotion_decision"])
            if state and state.get("pending_decision"):
                await self._settle_receipt(state)
                continue
            kind = ("novel_material_observation" if state is None else
                    "repeat_without_material_change" if state["material_digest"] == digest else
                    "material_change")
            revision = state["revision"] + 1 if state else 1
            decision = PromotionDecision(kind, kind != "repeat_without_material_change", key, digest, revision)
            receipt = {"observation_id": observation.observation_id, "decision": asdict(decision)}
            if state is None:
                try:
                    result = await self.db.observation_material_state.update_one(
                        {"material_key": key}, {"$setOnInsert": {
                            "material_key": key, "material_digest": digest,
                            "revision": 1, "pending_decision": receipt}}, upsert=True)
                except DuplicateKeyError:
                    continue
                if result.upserted_id is None:
                    continue
            else:
                result = await self.db.observation_material_state.update_one(
                    {"material_key": key, "revision": state["revision"],
                     "pending_decision": {"$exists": False}},
                    {"$set": {"material_digest": digest, "pending_decision": receipt},
                     "$inc": {"revision": 1}})
                if not result.modified_count:
                    continue
            # Re-read and finish the receipt; death here is repaired on replay.


def tvr_receipt_ref_for_observation(
    observation: CanonicalObservation,
    decision: PromotionDecision,
) -> dict[str, Any]:
    """Build a TVR-compatible receipt pointer for downstream proof packaging."""
    return {
        "schema": "seraph.tvr.receipt_ref.v1",
        "record_type": "technique_validation_record",
        "receipt_kind": "observation_promotion",
        "observation_id": observation.observation_id,
        "witness": observation.witness,
        "source_kind": observation.source_kind,
        "source_event_type": observation.source_event_type,
        "source_event_id": observation.source_event_id,
        "evidence_digest": observation.evidence_digest,
        "source": "observation_fabric",
        "promotion_event_type": "observation_promoted",
        "promotion_reason": decision.kind,
        "material_key": decision.material_key,
        "material_revision": decision.material_revision,
        "tvr_layer_targets": [
            "telemetry_evidence",
            "host_telemetry_evidence",
            "network_telemetry_evidence",
        ],
    }


class WorldObservationProjector:
    def __init__(self, db):
        self.db = db
        self.store = ObservationStore(db)

    async def _finish(self, observation, state, source_status):
        # Canonical completion is last so a failed source update is retryable.
        await self.db.suricata_alert_evidence.update_one(
            {"witness": observation.witness, "source_event_id": observation.source_event_id,
             "observation_id": observation.observation_id},
            {"$set": {"world_fanout_status": source_status}})
        await self.db.canonical_observations.update_one(
            {"observation_id": observation.observation_id},
            {"$set": {"promotion_state": state}})

    async def project(self, observation: CanonicalObservation, decision: PromotionDecision) -> dict:
        from backend.services.world_model import WorldModelService, WorldEntity, EntityType
        from backend.services.world_events import emit_world_event

        stored = await self.store.get(observation.observation_id)
        if stored is None or stored.get("promotion_decision") != asdict(decision):
            raise ValueError("Projection requires a durable promotion decision")
        if not decision.promote:
            await self._finish(observation, "retained_without_promotion", "retained_without_promotion")
            return {"projected": False, "triune_triggered": False}

        event_query = {"type": "observation_promoted", "payload.observation_id": observation.observation_id}
        existing = await self.db.world_events.find_one(event_query)
        if existing is None:
            if observation.witness == "unified_agent" and observation.source_event_type == "endpoint_evidence":
                entity_id = "endpoint-" + hashlib.sha256(decision.material_key.encode()).hexdigest()[:24]
                entity_type = EntityType.endpoint
            else:
                entity_id = "alert-" + hashlib.sha256(decision.material_key.encode()).hexdigest()[:24]
                entity_type = EntityType.alert

            observed = datetime.fromisoformat(observation.observed_at.replace("Z", "+00:00"))
            entity = WorldEntity(
                id=entity_id, type=entity_type, first_seen=observed, last_seen=observed,
                attributes={"schema": "seraph.observation.world.v1",
                            "observation_id": observation.observation_id,
                            "witness": observation.witness, "evidence_digest": observation.evidence_digest,
                            "observed_at": observation.observed_at,
                            "native_severity": observation.native_severity,
                            "native_confidence": observation.native_confidence,
                            "material_revision": decision.material_revision,
                            "tvr_receipt_ref": tvr_receipt_ref_for_observation(observation, decision),
                            "payload": observation.payload})
            try:
                await WorldModelService(self.db).upsert_entity(
                    entity, recalculate_risk=False, material_revision=decision.material_revision)
            except DuplicateKeyError:
                # A concurrent projector inserted this deterministic entity first.
                if await self.db.world_entities.find_one({"id": entity_id, "type": entity_type}) is None:
                    raise
            try:
                emitted = await emit_world_event(
                    self.db, "observation_promoted",
                    entity_refs=[entity_id, *observation.entity_refs],
                    payload={"schema": "seraph.observation.world.v1",
                             "observation_id": observation.observation_id,
                             "witness": observation.witness, "promotion_reason": decision.kind,
                             "evidence_digest": observation.evidence_digest,
                             "material_revision": decision.material_revision,
                             "material_key": decision.material_key,
                             "tvr_receipt_ref": tvr_receipt_ref_for_observation(observation, decision)},
                    trigger_triune=None, source="observation_fabric", strict_persistence=True)
                existing = emitted["event"]
            except DuplicateKeyError:
                existing = await self.db.world_events.find_one(event_query)
                if existing is None:
                    raise
        await self._finish(observation, "promoted", "emitted")
        return {"projected": True, "event_id": existing["id"],
                "triune_triggered": bool(existing.get("triune_triggered"))}
