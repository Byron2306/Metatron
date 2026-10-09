"""Unified Agent endpoint evidence adapter for the canonical observation rail."""
from __future__ import annotations

import logging
from typing import Any

from backend.services.observation_fabric import (
    CanonicalObservation,
    ObservationStore,
    build_observation,
)

logger = logging.getLogger(__name__)


def _endpoint_entity_refs(evidence: dict[str, Any]) -> list[str]:
    refs: list[str] = []

    agent_id = str(evidence.get("agent_id") or "").strip()
    node_id = str(evidence.get("node_id") or "").strip()
    hostname = str(evidence.get("hostname") or "").strip()

    if agent_id:
        refs.append(f"agent:{agent_id}")
    if node_id:
        refs.append(f"node:{node_id}")
    if hostname:
        refs.append(f"host:{hostname}")

    return list(dict.fromkeys(refs))


def unified_agent_endpoint_evidence_to_observation(evidence: dict[str, Any]) -> CanonicalObservation:
    """Convert source-native Unified Agent endpoint evidence into a canonical observation."""
    if evidence.get("schema") != "seraph.endpoint.evidence.v1":
        raise ValueError("Expected Unified Agent endpoint evidence schema")
    if evidence.get("source_kind") != "unified_agent":
        raise ValueError("Expected Unified Agent source_kind")

    agent_id = str(evidence.get("agent_id") or "").strip()
    timestamp = str(evidence.get("timestamp") or "").strip()
    if not agent_id:
        raise ValueError("Missing agent_id")
    if not timestamp:
        raise ValueError("Missing timestamp")

    payload = {
        key: value
        for key, value in evidence.items()
        if key not in {"_id", "world_fanout_status", "observation_id"}
    }

    threat_count = int(evidence.get("threat_count") or 0)
    native_severity = min(5, max(0, threat_count))

    return build_observation(
        witness="unified_agent",
        source_kind="endpoint_agent",
        source_event_type="endpoint_evidence",
        source_event_id=f"{agent_id}|{timestamp}",
        observed_at=timestamp,
        payload=payload,
        entity_refs=_endpoint_entity_refs(evidence),
        reconciliation_scope="endpoint_evidence",
        native_severity=native_severity,
        native_confidence=None,
        provenance="unified_agent_heartbeat",
    )


class AgentEndpointObservationBridge:
    def __init__(self, db):
        self.db = db
        self.store = ObservationStore(db)

    async def claim_pending(self, limit: int = 250) -> dict[str, int]:
        if limit < 1:
            raise ValueError("limit must be positive")

        result = {"claimed": 0, "reconciled": 0, "failed": 0}
        docs = await self.db.agent_endpoint_evidence.find(
            {"source_kind": "unified_agent", "world_fanout_status": "pending"}
        ).limit(limit).to_list(length=limit)

        for evidence in docs:
            try:
                observation = unified_agent_endpoint_evidence_to_observation(evidence)
                new = await self.store.claim(observation)
                status = "observed" if new else "reconciled"
                await self.db.agent_endpoint_evidence.update_one(
                    {"_id": evidence["_id"], "world_fanout_status": "pending"},
                    {"$set": {
                        "world_fanout_status": status,
                        "observation_id": observation.observation_id,
                    }},
                )
                result["claimed" if new else "reconciled"] += 1
            except Exception:
                logger.exception("Unified Agent endpoint observation claim failed; evidence remains retryable")
                result["failed"] += 1

        return result
