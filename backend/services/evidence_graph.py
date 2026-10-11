from __future__ import annotations

from typing import Any


def _clean_doc(doc: dict[str, Any] | None) -> dict[str, Any] | None:
    if not doc:
        return None
    out = dict(doc)
    out.pop("_id", None)
    return out


def _technique_id(value: str) -> str:
    text = str(value or "").strip().upper()
    if text and not text.startswith("T"):
        text = "T" + text
    return text


def _doc_technique(doc: dict[str, Any]) -> str:
    payload = doc.get("payload") or {}
    inner = payload.get("payload") or {}
    technique = (
        doc.get("technique_id")
        or payload.get("technique_id")
        or inner.get("technique_id")
        or (payload.get("technique") or {}).get("attack_id")
        or (inner.get("technique") or {}).get("attack_id")
        or ""
    )
    return _technique_id(technique)


def _matches_technique(doc: dict[str, Any], technique_id: str) -> bool:
    wanted = _technique_id(technique_id)
    if _doc_technique(doc) == wanted:
        return True
    refs = doc.get("entity_refs") or []
    return f"mitre:{wanted}" in refs


def _group_name(doc: dict[str, Any]) -> str:
    event_type = str(doc.get("source_event_type") or "")
    payload = doc.get("payload") or {}
    integration = str(payload.get("integration_name") or doc.get("provenance") or "")
    if event_type == "atomic_stdout" or integration == "atomic_red_team":
        return "atomic"
    if event_type == "osquery_query_catalog" or integration == "osquery":
        return "osquery"
    if event_type == "sigma_rule_match" or integration == "sigma":
        return "sigma"
    if event_type == "technique_validation_record" or integration == "tvr":
        return "tvr"
    if doc.get("witness") == "unified_agent":
        return "agent"
    if doc.get("witness") == "suricata":
        return "network"
    return integration or event_type or "other"


async def build_technique_evidence_graph(db, technique_id: str) -> dict[str, Any]:
    technique_id = _technique_id(technique_id)

    canonical = [
        _clean_doc(doc)
        for doc in await db.canonical_observations.find({}, {"_id": 0}).to_list(length=5000)
        if _matches_technique(doc, technique_id)
    ]

    canonical_ids = sorted({
        str(doc.get("observation_id"))
        for doc in canonical
        if doc and doc.get("observation_id")
    })

    by_source: dict[str, list[dict[str, Any]]] = {}
    for doc in canonical:
        by_source.setdefault(_group_name(doc), []).append(doc)

    tvr_observations = by_source.get("tvr", [])
    resolved_ids: list[str] = []
    missing_links: list[dict[str, Any]] = []

    for doc in tvr_observations:
        payload = doc.get("payload") or {}
        inner = payload.get("payload") or {}
        refs = inner.get("evidence_graph_refs") or payload.get("evidence_graph_refs") or {}
        for obs_id in refs.get("resolved_observation_ids") or []:
            if obs_id not in resolved_ids:
                resolved_ids.append(obs_id)
        for missing in refs.get("missing_links") or []:
            missing_links.append(missing)

    linked_observations = [
        doc for doc in canonical
        if doc.get("observation_id") in resolved_ids
    ]

    events = [
        _clean_doc(doc)
        for doc in await db.world_events.find({}, {"_id": 0}).to_list(length=5000)
        if _matches_technique(doc.get("payload") or {}, technique_id)
        or doc.get("payload", {}).get("observation_id") in canonical_ids
    ]

    entities = [
        _clean_doc(doc)
        for doc in await db.world_entities.find({}, {"_id": 0}).to_list(length=5000)
        if _matches_technique(doc.get("attributes") or {}, technique_id)
        or doc.get("attributes", {}).get("observation_id") in canonical_ids
    ]

    return {
        "schema": "seraph.evidence_graph.technique.v1",
        "technique_id": technique_id,
        "canonical_observation_count": len(canonical),
        "canonical_observation_ids": canonical_ids,
        "resolved_observation_ids": sorted(resolved_ids),
        "missing_links": missing_links,
        "sources": {key: value for key, value in sorted(by_source.items())},
        "tvr_observations": tvr_observations,
        "linked_observations": linked_observations,
        "world_events": events,
        "world_entities": entities,
    }
