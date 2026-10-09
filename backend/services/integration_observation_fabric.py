"""Integration evidence adapter for the canonical observation rail."""
from __future__ import annotations

import logging
from typing import Any

from backend.services.observation_fabric import (
    CanonicalObservation,
    ObservationStore,
    build_observation,
)

logger = logging.getLogger(__name__)


def _integration_entity_refs(evidence: dict[str, Any]) -> list[str]:
    technique_id = str(evidence.get("technique_id") or "").strip()
    return [f"mitre:{technique_id}"] if technique_id else []


def integration_evidence_to_observation(evidence: dict[str, Any]) -> CanonicalObservation:
    """Convert source-native integration evidence into a canonical observation."""
    if evidence.get("schema") != "seraph.integration.evidence.v1":
        raise ValueError("Expected integration evidence schema")
    if evidence.get("source_kind") != "integration_evidence":
        raise ValueError("Expected integration_evidence source_kind")

    integration_name = str(evidence.get("integration_name") or "").strip()
    evidence_type = str(evidence.get("evidence_type") or "").strip()
    technique_id = str(evidence.get("technique_id") or "").strip()
    timestamp = str(evidence.get("timestamp") or "").strip()

    if not integration_name:
        raise ValueError("Missing integration_name")
    if not evidence_type:
        raise ValueError("Missing evidence_type")
    if not technique_id:
        raise ValueError("Missing technique_id")
    if not timestamp:
        raise ValueError("Missing timestamp")

    payload = {
        key: value
        for key, value in evidence.items()
        if key not in {"_id", "world_fanout_status", "observation_id"}
    }

    return build_observation(
        witness="integration_evidence",
        source_kind="integration_evidence",
        source_event_type=evidence_type,
        source_event_id=f"{integration_name}|{evidence_type}|{technique_id}|{timestamp}",
        observed_at=timestamp,
        payload=payload,
        entity_refs=_integration_entity_refs(evidence),
        reconciliation_scope="integration_evidence",
        native_severity=evidence.get("severity"),
        native_confidence=evidence.get("confidence"),
        provenance=integration_name,
    )


class IntegrationObservationBridge:
    def __init__(self, db):
        self.db = db
        self.store = ObservationStore(db)

    async def claim_pending(self, limit: int = 250) -> dict[str, int]:
        if limit < 1:
            raise ValueError("limit must be positive")

        result = {"claimed": 0, "reconciled": 0, "failed": 0}
        docs = await self.db.integration_evidence.find(
            {"source_kind": "integration_evidence", "world_fanout_status": "pending"}
        ).limit(limit).to_list(length=limit)

        for evidence in docs:
            try:
                observation = integration_evidence_to_observation(evidence)
                new = await self.store.claim(observation)
                status = "observed" if new else "reconciled"
                await self.db.integration_evidence.update_one(
                    {"_id": evidence["_id"], "world_fanout_status": "pending"},
                    {"$set": {
                        "world_fanout_status": status,
                        "observation_id": observation.observation_id,
                    }},
                )
                result["claimed" if new else "reconciled"] += 1
            except Exception:
                logger.exception("Integration observation claim failed; evidence remains retryable")
                result["failed"] += 1

        return result
