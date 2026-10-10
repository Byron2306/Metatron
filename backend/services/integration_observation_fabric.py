"""Integration evidence adapter for the canonical observation rail."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from backend.services.observation_fabric import (
    CanonicalObservation,
    ObservationStore,
    build_observation,
)

logger = logging.getLogger(__name__)


def osquery_catalog_entry_to_integration_evidence(
    entry: dict[str, Any],
    *,
    technique_id: str,
    timestamp: str,
) -> dict[str, Any]:
    """Normalize an ATT&CK-mapped osquery catalog row into integration evidence."""
    technique_id = str(technique_id or "").strip()
    timestamp = str(timestamp or "").strip()
    query_name = str(
        entry.get("name")
        or entry.get("query_name")
        or entry.get("id")
        or entry.get("title")
        or ""
    ).strip()
    query = str(entry.get("query") or entry.get("sql") or "").strip()

    if not technique_id:
        raise ValueError("Missing technique_id")
    if not timestamp:
        raise ValueError("Missing timestamp")
    if not query_name:
        raise ValueError("Missing osquery query name")
    if not query:
        raise ValueError("Missing osquery query")

    techniques = entry.get("attack_techniques") or entry.get("techniques") or []
    if isinstance(techniques, str):
        techniques = [techniques]
    techniques = [str(item).strip() for item in techniques if str(item).strip()]

    return {
        "schema": "seraph.integration.evidence.v1",
        "source_kind": "integration_evidence",
        "integration_name": "osquery",
        "evidence_type": "osquery_query_catalog",
        "technique_id": technique_id,
        "timestamp": timestamp,
        "payload": {
            "query_name": query_name,
            "description": entry.get("description"),
            "query": query,
            "attack_techniques": techniques,
            "platform": entry.get("platform"),
            "interval": entry.get("interval"),
        },
        "world_fanout_status": "pending",
    }


def _walk_json(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json(child)


def load_osquery_catalog_integration_evidence(
    catalog_path: str | Path,
    *,
    timestamp: str,
) -> list[dict[str, Any]]:
    """Load ATT&CK-mapped osquery catalog entries as normalized integration evidence."""
    path = Path(catalog_path)
    data = json.loads(path.read_text())

    docs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for entry in _walk_json(data):
        query = entry.get("query") or entry.get("sql")
        if not query:
            continue

        techniques = entry.get("attack_techniques") or entry.get("techniques") or []
        if isinstance(techniques, str):
            techniques = [techniques]

        for technique_id in techniques:
            technique_id = str(technique_id or "").strip()
            if not technique_id:
                continue
            doc = osquery_catalog_entry_to_integration_evidence(
                entry,
                technique_id=technique_id,
                timestamp=timestamp,
            )
            key = (doc["technique_id"], doc["payload"]["query_name"])
            if key in seen:
                continue
            seen.add(key)
            docs.append(doc)

    return docs


def _technique_from_sigma_path(path: str | Path | None) -> str:
    if path is None:
        return ""
    parts = Path(str(path)).parts
    for index, part in enumerate(parts):
        if part == "techniques" and index + 1 < len(parts):
            candidate = str(parts[index + 1]).strip()
            if candidate.startswith("T"):
                return candidate
    return ""


def sigma_match_to_integration_evidence(
    match: dict[str, Any],
    *,
    technique_id: str | None = None,
    source_path: str | Path | None = None,
) -> dict[str, Any]:
    """Normalize Sigma live/contextual match records into integration evidence."""
    rule_id = str(
        match.get("rule_id")
        or match.get("sigma_rule_id")
        or match.get("source_id")
        or match.get("analytic_id")
        or ""
    ).strip()
    title = str(match.get("title") or match.get("name") or "").strip()
    resolved_technique = str(
        technique_id
        or match.get("technique")
        or match.get("technique_id")
        or match.get("mitre_technique")
        or _technique_from_sigma_path(source_path)
        or ""
    ).strip()
    timestamp = str(
        match.get("timestamp")
        or match.get("matched_event", {}).get("timestamp")
        or "1970-01-01T00:00:00+00:00"
    ).strip()

    if not rule_id:
        raise ValueError("Missing Sigma rule_id")
    if not title:
        raise ValueError("Missing Sigma title")
    if not resolved_technique:
        raise ValueError("Missing Sigma technique_id")
    if not timestamp:
        raise ValueError("Missing Sigma timestamp")

    payload = {
        "rule_id": rule_id,
        "title": title,
        "rule_file": match.get("rule_file"),
        "rule_sha256": match.get("rule_sha256"),
        "source_id": match.get("source_id"),
        "analytic_id": match.get("analytic_id"),
        "match_type": match.get("match_type"),
        "match_count": match.get("match_count"),
        "matched": match.get("matched"),
        "live_sigma_evaluation": match.get("live_sigma_evaluation"),
        "detection_basis": match.get("detection_basis") or match.get("sigma_detection_basis"),
        "sigma_telemetry_source": match.get("sigma_telemetry_source"),
        "level": match.get("level"),
        "status": match.get("status"),
        "source": match.get("source"),
        "matched_event": match.get("matched_event"),
        "supporting_event_ids": match.get("supporting_event_ids"),
        "source_path": str(source_path) if source_path is not None else None,
    }

    return {
        "schema": "seraph.integration.evidence.v1",
        "source_kind": "integration_evidence",
        "integration_name": "sigma",
        "evidence_type": "sigma_rule_match",
        "technique_id": resolved_technique,
        "timestamp": timestamp,
        "payload": payload,
        "world_fanout_status": "pending",
    }


def load_sigma_matches_integration_evidence(
    sigma_match_paths: list[str | Path],
) -> list[dict[str, Any]]:
    """Load Sigma live/contextual match files as normalized integration evidence."""
    docs: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    for sigma_path in sigma_match_paths:
        path = Path(sigma_path)
        data = json.loads(path.read_text())
        items = data if isinstance(data, list) else (
            data.get("matches")
            or data.get("results")
            or data.get("sigma_matches")
            or []
        )
        if isinstance(items, dict):
            items = list(items.values())
        if not isinstance(items, list):
            continue

        path_technique = _technique_from_sigma_path(path)
        for item in items:
            if not isinstance(item, dict):
                continue
            doc = sigma_match_to_integration_evidence(
                item,
                technique_id=path_technique or None,
                source_path=path,
            )
            key = (
                doc["technique_id"],
                doc["timestamp"],
                doc["payload"]["rule_id"],
                str(doc["payload"].get("source_path") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            docs.append(doc)

    return docs


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

    async def ingest_osquery_catalog(
        self,
        catalog_path: str | Path,
        *,
        timestamp: str,
        limit: int = 250,
    ) -> dict[str, int | bool]:
        docs = load_osquery_catalog_integration_evidence(
            catalog_path,
            timestamp=timestamp,
        )

        result: dict[str, int | bool] = {
            "ingested": True,
            "loaded": len(docs),
            "inserted": 0,
            "duplicates": 0,
            "claimed": 0,
            "reconciled": 0,
            "failed": 0,
        }

        for doc in docs:
            query = {
                "source_kind": "integration_evidence",
                "integration_name": doc["integration_name"],
                "evidence_type": doc["evidence_type"],
                "technique_id": doc["technique_id"],
                "timestamp": doc["timestamp"],
                "payload.query_name": doc["payload"]["query_name"],
            }
            try:
                write = await self.db.integration_evidence.update_one(
                    query,
                    {"$setOnInsert": doc},
                    upsert=True,
                )
                if write.upserted_id is not None:
                    result["inserted"] = int(result["inserted"]) + 1
                else:
                    result["duplicates"] = int(result["duplicates"]) + 1
            except Exception:
                logger.exception("Osquery catalog evidence insert failed")
                result["failed"] = int(result["failed"]) + 1

        claim = await self.claim_pending(limit=limit)
        result["claimed"] = int(claim["claimed"])
        result["reconciled"] = int(claim["reconciled"])
        result["failed"] = int(result["failed"]) + int(claim["failed"])
        return result

    async def ingest_sigma_matches(
        self,
        sigma_match_paths: list[str | Path],
        *,
        limit: int = 250,
    ) -> dict[str, int | bool]:
        docs = load_sigma_matches_integration_evidence(sigma_match_paths)

        result: dict[str, int | bool] = {
            "ingested": True,
            "loaded": len(docs),
            "inserted": 0,
            "duplicates": 0,
            "claimed": 0,
            "reconciled": 0,
            "failed": 0,
        }

        for doc in docs:
            query = {
                "source_kind": "integration_evidence",
                "integration_name": doc["integration_name"],
                "evidence_type": doc["evidence_type"],
                "technique_id": doc["technique_id"],
                "timestamp": doc["timestamp"],
                "payload.rule_id": doc["payload"]["rule_id"],
                "payload.source_path": doc["payload"]["source_path"],
            }
            try:
                write = await self.db.integration_evidence.update_one(
                    query,
                    {"$setOnInsert": doc},
                    upsert=True,
                )
                if write.upserted_id is not None:
                    result["inserted"] = int(result["inserted"]) + 1
                else:
                    result["duplicates"] = int(result["duplicates"]) + 1
            except Exception:
                logger.exception("Sigma match evidence insert failed")
                result["failed"] = int(result["failed"]) + 1

        claim = await self.claim_pending(limit=limit)
        result["claimed"] = int(claim["claimed"])
        result["reconciled"] = int(claim["reconciled"])
        result["failed"] = int(result["failed"]) + int(claim["failed"])
        return result

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
