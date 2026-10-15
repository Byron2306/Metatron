"""Integration evidence adapter for the canonical observation rail."""
from __future__ import annotations

import json
import hashlib
import logging
from pathlib import Path
from typing import Any

from backend.services.observation_fabric import (
    CanonicalObservation,
    ObservationStore,
    build_observation,
    canonical_json,
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



def _technique_from_tvr_record(
    record: dict[str, Any],
    source_path: str | Path | None = None,
) -> str:
    technique = record.get("technique")
    if isinstance(technique, dict):
        for key in ("attack_id", "id", "technique_id", "external_id", "name"):
            value = str(technique.get(key) or "").strip()
            if value.startswith("T"):
                return value
    elif isinstance(technique, str) and technique.strip().startswith("T"):
        return technique.strip()

    if source_path is not None:
        for part in Path(str(source_path)).parts:
            if part.startswith("T"):
                return part
    return ""



def _list_unique(values: list[Any]) -> list[Any]:
    result = []
    for value in values:
        if value in (None, "", [], {}):
            continue
        if value not in result:
            result.append(value)
    return result


def _tvr_receipt_links(record: dict[str, Any]) -> dict[str, Any]:
    execution = record.get("execution") or {}
    analytic = record.get("analytic_evidence") or {}
    host = record.get("host_telemetry_evidence") or {}
    network = record.get("network_telemetry_evidence") or {}
    artifacts = record.get("artifact_evidence") or {}
    response = record.get("response_evidence") or {}
    correlation = record.get("correlation") or {}

    runs = execution.get("runs") or []
    if not isinstance(runs, list):
        runs = []

    osquery_items = analytic.get("osquery") or []
    if not isinstance(osquery_items, list):
        osquery_items = []

    sigma_items = analytic.get("sigma") or []
    if not isinstance(sigma_items, list):
        sigma_items = []

    files = artifacts.get("files") or []
    if not isinstance(files, list):
        files = []

    actions = response.get("actions") or []
    if not isinstance(actions, list):
        actions = []

    anchors = correlation.get("anchors") if isinstance(correlation, dict) else {}
    if not isinstance(anchors, dict):
        anchors = {}

    return {
        "atomic": {
            "run_ids": _list_unique(
                list(execution.get("run_ids") or [])
                + [run.get("run_id") for run in runs if isinstance(run, dict)]
            ),
            "job_ids": _list_unique(
                list(execution.get("job_ids") or [])
                + [run.get("job_id") for run in runs if isinstance(run, dict)]
            ),
            "stdout_sha256": _list_unique(
                [run.get("stdout_sha256") for run in runs if isinstance(run, dict)]
            ),
        },
        "osquery": [
            {
                "query_id": item.get("query_id"),
                "name": item.get("name"),
                "supporting_event_ids": list(item.get("supporting_event_ids") or []),
                "result_count": item.get("result_count"),
            }
            for item in osquery_items
            if isinstance(item, dict)
        ],
        "sigma": [
            {
                "rule_id": item.get("rule_id"),
                "rule_sha256": item.get("rule_sha256"),
                "supporting_event_ids": list(item.get("supporting_event_ids") or []),
                "detection_basis": item.get("detection_basis"),
            }
            for item in sigma_items
            if isinstance(item, dict)
        ],
        "host": {
            key: host.get(key)
            for key in ("agent_id", "node_id", "hostname", "supporting_event_ids")
            if host.get(key) not in (None, "", [], {})
        },
        "network": {
            key: list(network.get(key) or [])
            for key in ("zeek_uids", "arkime_session_ids", "suricata_source_event_ids")
            if network.get(key)
        },
        "artifacts": {
            "paths": _list_unique([
                item.get("path") for item in files if isinstance(item, dict)
            ]),
            "file_sha256": _list_unique([
                (item.get("hashes") or {}).get("sha256")
                for item in files
                if isinstance(item, dict)
            ]),
        },
        "response": {
            "action_ids": _list_unique([
                item.get("action_id") for item in actions if isinstance(item, dict)
            ]),
        },
        "correlation": {
            key: value
            for key, value in anchors.items()
            if value not in (None, "", [], {})
        },
    }


def tvr_record_to_integration_evidence(
    record: dict[str, Any],
    *,
    source_path: str | Path | None = None,
) -> dict[str, Any]:
    """Normalize a Technique Validation Record into integration evidence."""
    validation_id = str(record.get("validation_id") or "").strip()
    technique_id = _technique_from_tvr_record(record, source_path)
    execution = record.get("execution") or {}
    integrity = record.get("integrity") or {}
    timestamp = str(
        execution.get("started_at")
        or execution.get("ended_at")
        or integrity.get("created_at")
        or "1970-01-01T00:00:00+00:00"
    ).strip()

    if record.get("record_type") != "technique_validation_record":
        raise ValueError("Expected technique_validation_record")
    if not validation_id:
        raise ValueError("Missing TVR validation_id")
    if not technique_id:
        raise ValueError("Missing TVR technique_id")

    return {
        "schema": "seraph.integration.evidence.v1",
        "source_kind": "integration_evidence",
        "integration_name": "tvr",
        "evidence_type": "technique_validation_record",
        "technique_id": technique_id,
        "timestamp": timestamp,
        "source_event_id": f"tvr|technique_validation_record|{validation_id}",
        "payload": {
            "validation_id": validation_id,
            "record_type": record.get("record_type"),
            "schema_version": record.get("schema_version"),
            "technique": record.get("technique"),
            "procedure": record.get("procedure"),
            "execution": execution,
            "quality": record.get("quality"),
            "integrity": integrity,
            "record_sha256": integrity.get("record_sha256"),
            "analytic_evidence": record.get("analytic_evidence"),
            "detection_evidence": record.get("detection_evidence"),
            "artifact_evidence": record.get("artifact_evidence"),
            "response_evidence": record.get("response_evidence"),
            "correlation": record.get("correlation"),
            "promotion": record.get("promotion"),
            "receipt_links": _tvr_receipt_links(record),
            "source_path": str(source_path) if source_path is not None else None,
        },
        "world_fanout_status": "pending",
    }


def load_tvr_records_integration_evidence(
    tvr_paths: list[str | Path],
) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    seen: set[str] = set()

    for tvr_path in tvr_paths:
        source_path = Path(tvr_path)
        doc = tvr_record_to_integration_evidence(
            json.loads(source_path.read_text()),
            source_path=source_path,
        )
        if doc["source_event_id"] in seen:
            continue
        seen.add(doc["source_event_id"])
        docs.append(doc)

    return docs


def atomic_stdout_event_to_integration_evidence(
    event: dict[str, Any],
    *,
    technique_id: str,
    validation_id: str,
    source_path: str | Path | None = None,
) -> dict[str, Any]:
    run_id = str(event.get("run_id") or "").strip()
    stdout_sha256 = str(event.get("stdout_sha256") or "").strip()
    timestamp = str(event.get("finished_at") or "1970-01-01T00:00:00+00:00").strip()
    technique_id = str(technique_id or "").strip()
    validation_id = str(validation_id or "").strip()

    if not technique_id:
        raise ValueError("Missing atomic technique_id")
    if not validation_id:
        raise ValueError("Missing atomic validation_id")
    if not run_id:
        raise ValueError("Missing atomic run_id")
    if not stdout_sha256:
        raise ValueError("Missing atomic stdout_sha256")

    return {
        "schema": "seraph.integration.evidence.v1",
        "source_kind": "integration_evidence",
        "integration_name": "atomic_red_team",
        "evidence_type": "atomic_stdout",
        "technique_id": technique_id,
        "timestamp": timestamp,
        "source_event_id": (
            f"atomic_red_team|atomic_stdout|{validation_id}|{run_id}|{stdout_sha256}"
        ),
        "payload": {
            "validation_id": validation_id,
            "run_id": run_id,
            "job_id": event.get("job_id"),
            "job_name": event.get("job_name"),
            "finished_at": event.get("finished_at"),
            "exit_code": event.get("exit_code"),
            "sandbox": event.get("sandbox"),
            "stdout": event.get("stdout"),
            "stdout_sha256": stdout_sha256,
            "source_path": str(source_path) if source_path is not None else None,
        },
        "world_fanout_status": "pending",
    }


def load_atomic_stdout_integration_evidence(
    atomic_stdout_paths: list[str | Path],
    *,
    technique_id: str,
    validation_id: str,
) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    seen: set[str] = set()

    for atomic_path in atomic_stdout_paths:
        source_path = Path(atomic_path)
        for line in source_path.read_text().splitlines():
            if not line.strip():
                continue
            doc = atomic_stdout_event_to_integration_evidence(
                json.loads(line),
                technique_id=technique_id,
                validation_id=validation_id,
                source_path=source_path,
            )
            if doc["source_event_id"] in seen:
                continue
            seen.add(doc["source_event_id"])
            docs.append(doc)

    return docs


async def resolve_tvr_receipt_observation_refs(db, tvr_evidence: dict[str, Any]) -> dict[str, Any]:
    """Resolve TVR receipt links to canonical observation ids for proof packaging."""
    payload = tvr_evidence.get("payload") or {}
    links = payload.get("receipt_links") or {}
    validation_id = str(payload.get("validation_id") or tvr_evidence.get("validation_id") or "").strip()
    technique_id = str(tvr_evidence.get("technique_id") or payload.get("technique_id") or "").strip()

    resolved: list[str] = []
    missing: list[dict[str, Any]] = []

    async def add_matches(label: str, query: dict[str, Any], *, required: bool = True) -> None:
        docs = await db.canonical_observations.find(
            query,
            {"_id": 0, "observation_id": 1},
        ).to_list(length=1000)
        if not docs:
            if required:
                missing.append({"link_type": label, "query": query})
            return
        for doc in docs:
            observation_id = doc.get("observation_id")
            if observation_id and observation_id not in resolved:
                resolved.append(observation_id)

    atomic_links = links.get("atomic") or {}
    atomic_items: list[dict[str, Any]] = []
    if isinstance(atomic_links, dict):
        for run_id in atomic_links.get("run_ids") or []:
            atomic_items.append({"run_id": run_id})
    elif isinstance(atomic_links, list):
        atomic_items = [item for item in atomic_links if isinstance(item, dict)]

    for item in atomic_items:
        run_id = str(item.get("run_id") or "").strip()
        query = {
            "witness": "integration_evidence",
            "source_event_type": "atomic_stdout",
            "payload.payload.validation_id": validation_id,
        }
        if run_id:
            query["payload.payload.run_id"] = run_id
        await add_matches("atomic", query)

    osquery_links = links.get("osquery") or []
    if isinstance(osquery_links, dict):
        osquery_links = [osquery_links]
    for item in [item for item in osquery_links if isinstance(item, dict)]:
        query_name = str(item.get("query_name") or item.get("name") or "").strip()
        query = {
            "witness": "integration_evidence",
            "source_event_type": "osquery_query_catalog",
            "payload.technique_id": technique_id,
        }
        if query_name:
            query["payload.payload.query_name"] = query_name
        await add_matches("osquery", query)

    sigma_links = links.get("sigma") or []
    if isinstance(sigma_links, dict):
        sigma_links = [sigma_links]
    for item in [item for item in sigma_links if isinstance(item, dict)]:
        rule_id = str(item.get("rule_id") or item.get("id") or "").strip()
        query = {
            "witness": "integration_evidence",
            "source_event_type": "sigma_rule_match",
            "payload.technique_id": technique_id,
        }
        if rule_id:
            query["payload.payload.rule_id"] = rule_id
        await add_matches("sigma", query)

    if technique_id and not osquery_links:
        await add_matches("osquery", {
            "witness": "integration_evidence",
            "source_event_type": "osquery_query_catalog",
            "payload.technique_id": technique_id,
        }, required=False)

    if technique_id and not sigma_links:
        await add_matches("sigma", {
            "witness": "integration_evidence",
            "source_event_type": "sigma_rule_match",
            "payload.technique_id": technique_id,
        }, required=False)

    return {
        "schema": "seraph.tvr.evidence_graph_refs.v1",
        "validation_id": validation_id,
        "technique_id": technique_id,
        "resolved_observation_ids": sorted(resolved),
        "missing_links": missing,
    }



_INTEGRATION_TOOL_RESULT_TOOLS = {
    "amass", "arkime", "bloodhound", "clamav", "falco", "purplesharp",
    "spiderfoot", "trivy", "velociraptor", "yara", "zeek",
}

_INTEGRATION_TECHNIQUE_KEYS = {
    "technique", "technique_id", "mitre_technique", "attack_technique",
}

_INTEGRATION_TECHNIQUE_LIST_KEYS = {
    "techniques", "technique_ids", "mitre_techniques",
    "attack_techniques", "validated_techniques",
}


def _normalise_attack_technique(value: Any) -> str:
    text = str(value or "").strip().upper()
    if text.startswith("MITRE:"):
        text = text.split(":", 1)[1]
    if text and not text.startswith("T") and text[0].isdigit():
        text = "T" + text
    return text if text.startswith("T") else ""


def _collect_attack_techniques(value: Any) -> list[str]:
    found: list[str] = []

    def add(candidate: Any) -> None:
        technique = _normalise_attack_technique(candidate)
        if technique and technique not in found:
            found.append(technique)

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                key_text = str(key or "").strip().lower()
                if key_text in _INTEGRATION_TECHNIQUE_KEYS:
                    add(child)
                elif key_text in _INTEGRATION_TECHNIQUE_LIST_KEYS and isinstance(child, list):
                    for entry in child:
                        add(entry)
                else:
                    walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)
    return found


def integration_tool_result_source_event_id(evidence: dict[str, Any]) -> str:
    payload = evidence.get("payload") or {}
    tool = str(evidence.get("integration_name") or payload.get("tool") or "integration").strip()
    evidence_type = str(evidence.get("evidence_type") or "integration_tool_result").strip()
    technique_id = str(evidence.get("technique_id") or "").strip()
    job_id = str(payload.get("job_id") or "job-unknown").strip()
    action = str(payload.get("action") or "unknown").strip()
    return f"{tool}|{evidence_type}|{technique_id}|{job_id}|{action}"


def integration_tool_result_to_integration_evidence(
    job: dict[str, Any],
    *,
    technique_id: str | None = None,
) -> list[dict[str, Any]]:
    tool = str(job.get("tool") or "").strip().lower()
    if tool not in _INTEGRATION_TOOL_RESULT_TOOLS:
        return []

    params = job.get("params") or {}
    result = job.get("result") or {}

    techniques = []
    supplied = _normalise_attack_technique(technique_id)
    if supplied:
        techniques.append(supplied)

    for discovered in _collect_attack_techniques({"params": params, "result": result}):
        if discovered not in techniques:
            techniques.append(discovered)

    if not techniques:
        return []

    job_id = str(job.get("id") or job.get("job_id") or "").strip()
    if not job_id:
        job_id = hashlib.sha256(canonical_json(job).encode()).hexdigest()[:16]

    action = str(
        (params.get("action") if isinstance(params, dict) else "")
        or (result.get("action") if isinstance(result, dict) else "")
        or "unknown"
    ).strip().lower()

    timestamp = str(
        job.get("updated_at")
        or job.get("created_at")
        or "1970-01-01T00:00:00+00:00"
    ).strip()

    docs = []
    for attack_id in techniques:
        doc = {
            "schema": "seraph.integration.evidence.v1",
            "source_kind": "integration_evidence",
            "integration_name": tool,
            "evidence_type": "integration_tool_result",
            "technique_id": attack_id,
            "timestamp": timestamp,
            "payload": {
                "tool": tool,
                "job_id": job_id,
                "action": action,
                "status": job.get("status"),
                "params": params,
                "result": result,
                "source_collection": "integrations_jobs",
            },
            "world_fanout_status": "pending",
        }
        doc["source_event_id"] = integration_tool_result_source_event_id(doc)
        docs.append(doc)

    return docs


def soar_execution_source_event_id(evidence: dict[str, Any]) -> str:
    payload = evidence.get("payload") or {}
    technique_id = str(evidence.get("technique_id") or "").strip()
    execution_id = str(payload.get("execution_id") or "execution-unknown").strip()
    return f"soar|soar_response_effect|{technique_id}|{execution_id}"


def soar_execution_to_integration_evidence(
    execution: dict[str, Any],
    *,
    technique_id: str | None = None,
) -> list[dict[str, Any]]:
    """Normalize durable SOAR requested-vs-actual receipts onto the evidence rail."""
    if not execution:
        return []

    trigger_event = execution.get("trigger_event") or {}
    techniques: list[str] = []
    supplied = _normalise_attack_technique(technique_id)
    if supplied:
        techniques.append(supplied)
    for discovered in _collect_attack_techniques(trigger_event):
        if discovered not in techniques:
            techniques.append(discovered)
    if not techniques:
        return []

    execution_id = str(execution.get("id") or execution.get("execution_id") or "").strip()
    if not execution_id:
        execution_id = hashlib.sha256(canonical_json(execution).encode()).hexdigest()[:16]

    timestamp = str(
        execution.get("completed_at")
        or execution.get("started_at")
        or "1970-01-01T00:00:00+00:00"
    ).strip()
    actual = execution.get("actual_effect_receipt") or {}
    outcome = str(
        actual.get("effect_verification")
        or execution.get("status")
        or "unknown"
    ).strip().lower()

    docs: list[dict[str, Any]] = []
    for attack_id in techniques:
        doc = {
            "schema": "seraph.integration.evidence.v1",
            "source_kind": "integration_evidence",
            "integration_name": "soar",
            "evidence_type": "soar_response_effect",
            "technique_id": attack_id,
            "timestamp": timestamp,
            "severity": trigger_event.get("severity"),
            "confidence": execution.get("ai_confidence"),
            "payload": {
                "execution_id": execution_id,
                "playbook_id": execution.get("playbook_id"),
                "playbook_name": execution.get("playbook_name"),
                "execution_status": execution.get("status"),
                "semantic_response_state": execution.get("semantic_response_state"),
                "response_outcome": outcome,
                "trigger_event": trigger_event,
                "requested_response": execution.get("requested_response") or {},
                "orchestration_receipt": execution.get("orchestration_receipt") or {},
                "actual_effect_receipt": actual,
                "source_collection": "soar_executions",
            },
            "world_fanout_status": "pending",
        }
        doc["source_event_id"] = soar_execution_source_event_id(doc)
        docs.append(doc)
    return docs


def _plain_value(value: Any) -> Any:
    return getattr(value, "value", value)


def ml_prediction_source_event_id(evidence: dict[str, Any]) -> str:
    payload = evidence.get("payload") or {}
    technique_id = str(evidence.get("technique_id") or "").strip()
    prediction_id = str(payload.get("prediction_id") or "prediction-unknown").strip()
    return f"ml|ml_prediction|{technique_id}|{prediction_id}"


def ml_prediction_to_integration_evidence(
    prediction: dict[str, Any],
    *,
    technique_id: str | None = None,
) -> list[dict[str, Any]]:
    """Normalize ML predictions into integration evidence for the canonical rail."""
    if not prediction:
        return []

    prediction = {
        key: _plain_value(value)
        for key, value in prediction.items()
        if key != "_id"
    }

    techniques: list[str] = []
    supplied = _normalise_attack_technique(technique_id)
    if supplied:
        techniques.append(supplied)
    for discovered in _collect_attack_techniques(prediction):
        if discovered not in techniques:
            techniques.append(discovered)
    if not techniques:
        return []

    prediction_id = str(prediction.get("prediction_id") or "").strip()
    if not prediction_id:
        prediction_id = hashlib.sha256(canonical_json(prediction).encode()).hexdigest()[:16]

    timestamp = str(
        prediction.get("timestamp")
        or prediction.get("created_at")
        or "1970-01-01T00:00:00+00:00"
    ).strip()

    docs = []
    for attack_id in techniques:
        doc = {
            "schema": "seraph.integration.evidence.v1",
            "source_kind": "integration_evidence",
            "integration_name": "ml",
            "evidence_type": "ml_prediction",
            "technique_id": attack_id,
            "timestamp": timestamp,
            "severity": _plain_value(prediction.get("risk_level")),
            "confidence": prediction.get("confidence"),
            "payload": {
                **prediction,
                "prediction_id": prediction_id,
                "entity_type": prediction.get("entity_type"),
                "entity_id": prediction.get("entity_id"),
                "source_collection": "ml_predictions",
            },
            "world_fanout_status": "pending",
        }
        doc["source_event_id"] = ml_prediction_source_event_id(doc)
        docs.append(doc)

    return docs


def honeytoken_access_source_event_id(evidence: dict[str, Any]) -> str:
    payload = evidence.get("payload") or {}
    technique_id = str(evidence.get("technique_id") or "").strip()
    access_id = str(payload.get("access_id") or "access-unknown").strip()
    return f"honeytoken|honey_token_access|{technique_id}|{access_id}"


def honeytoken_access_to_integration_evidence(
    access: dict[str, Any],
    *,
    technique_id: str | None = None,
) -> dict[str, Any] | None:
    access_id = str(access.get("id") or access.get("access_id") or "").strip()
    if not access_id:
        return None

    resolved_technique = (
        _normalise_attack_technique(technique_id)
        or _normalise_attack_technique(access.get("technique_id"))
        or "T1552"
    )
    timestamp = str(
        access.get("accessed_at")
        or access.get("timestamp")
        or access.get("created_at")
        or "1970-01-01T00:00:00+00:00"
    ).strip()

    doc = {
        "schema": "seraph.integration.evidence.v1",
        "source_kind": "integration_evidence",
        "integration_name": "honeytoken",
        "evidence_type": "honey_token_access",
        "technique_id": resolved_technique,
        "timestamp": timestamp,
        "severity": access.get("severity") or "critical",
        "confidence": access.get("confidence") or 1.0,
        "payload": {
            "access_id": access_id,
            "token_id": access.get("token_id"),
            "token_name": access.get("token_name"),
            "token_type": access.get("token_type"),
            "source_ip": access.get("source_ip"),
            "user_agent": access.get("user_agent"),
            "request_path": access.get("request_path"),
            "request_method": access.get("request_method"),
            "headers": access.get("headers") or {},
            "deception_case_id": access.get("deception_case_id"),
            "deception_event_id": access.get("deception_event_id") or access.get("event_id"),
            "campaign_id": access.get("campaign_id"),
            "source_collection": "honey_token_accesses",
        },
        "world_fanout_status": "pending",
    }
    doc["source_event_id"] = honeytoken_access_source_event_id(doc)
    return doc


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
        source_event_id=str(
            evidence.get("source_event_id")
            or f"{integration_name}|{evidence_type}|{technique_id}|{timestamp}"
        ),
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

    async def _insert_integration_docs(
        self,
        docs: list[dict[str, Any]],
        *,
        limit: int,
    ) -> dict[str, int | bool]:
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
            try:
                write = await self.db.integration_evidence.update_one(
                    {
                        "source_kind": "integration_evidence",
                        "source_event_id": doc["source_event_id"],
                    },
                    {"$setOnInsert": doc},
                    upsert=True,
                )
                if write.upserted_id is not None:
                    result["inserted"] = int(result["inserted"]) + 1
                else:
                    result["duplicates"] = int(result["duplicates"]) + 1
            except Exception:
                logger.exception("Integration evidence insert failed")
                result["failed"] = int(result["failed"]) + 1

        claim = await self.claim_pending(limit=limit)
        result["claimed"] = int(claim["claimed"])
        result["reconciled"] = int(claim["reconciled"])
        result["failed"] = int(result["failed"]) + int(claim["failed"])
        return result

    async def ingest_tvr_records(
        self,
        tvr_paths: list[str | Path],
        *,
        limit: int = 250,
    ) -> dict[str, int | bool]:
        docs = load_tvr_records_integration_evidence(tvr_paths)

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
            try:
                doc["payload"]["evidence_graph_refs"] = await resolve_tvr_receipt_observation_refs(
                    self.db,
                    doc,
                )
            except Exception:
                logger.exception("TVR evidence graph resolution failed")
                doc["payload"]["evidence_graph_refs"] = {
                    "schema": "seraph.tvr.evidence_graph_refs.v1",
                    "validation_id": doc.get("payload", {}).get("validation_id"),
                    "technique_id": doc.get("technique_id"),
                    "resolved_observation_ids": [],
                    "missing_links": [{"link_type": "resolver_error"}],
                }

            query = {
                "source_kind": "integration_evidence",
                "integration_name": doc["integration_name"],
                "evidence_type": doc["evidence_type"],
                "technique_id": doc["technique_id"],
                "timestamp": doc["timestamp"],
                "payload.validation_id": doc["payload"]["validation_id"],
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
                logger.exception("TVR evidence insert failed")
                result["failed"] = int(result["failed"]) + 1

        claim = await self.claim_pending(limit=limit)
        result["claimed"] = int(claim["claimed"])
        result["reconciled"] = int(claim["reconciled"])
        result["failed"] = int(result["failed"]) + int(claim["failed"])
        return result


    async def ingest_atomic_stdout(
        self,
        atomic_stdout_paths: list[str | Path],
        *,
        technique_id: str,
        validation_id: str,
        limit: int = 250,
    ) -> dict[str, int | bool]:
        return await self._insert_integration_docs(
            load_atomic_stdout_integration_evidence(
                atomic_stdout_paths,
                technique_id=technique_id,
                validation_id=validation_id,
            ),
            limit=limit,
        )

    async def ingest_completed_tool_jobs(
        self,
        *,
        tool: str | None = None,
        technique_id: str | None = None,
        limit: int = 250,
    ) -> dict[str, int | bool]:
        query: dict[str, Any] = {"status": "completed"}
        if tool:
            query["tool"] = str(tool).strip().lower()

        jobs = await self.db.integrations_jobs.find(query).limit(limit).to_list(length=limit)
        docs: list[dict[str, Any]] = []
        for job in jobs:
            docs.extend(
                integration_tool_result_to_integration_evidence(
                    job,
                    technique_id=technique_id,
                )
            )

        return await self._insert_integration_docs(docs, limit=limit)

    async def ingest_soar_executions(
        self,
        *,
        execution_id: str | None = None,
        technique_id: str | None = None,
        limit: int = 250,
    ) -> dict[str, int | bool]:
        query: dict[str, Any] = {
            "status": {"$in": ["completed", "partial", "failed", "escalated"]},
            "actual_effect_receipt": {"$exists": True},
        }
        if execution_id:
            query["id"] = str(execution_id).strip()

        executions = await self.db.soar_executions.find(query).limit(limit).to_list(length=limit)
        docs: list[dict[str, Any]] = []
        for execution in executions:
            docs.extend(
                soar_execution_to_integration_evidence(
                    execution,
                    technique_id=technique_id,
                )
            )

        result = await self._insert_integration_docs(docs, limit=limit)
        for doc in docs:
            evidence = await self.db.integration_evidence.find_one({
                "source_kind": "integration_evidence",
                "source_event_id": doc["source_event_id"],
            })
            if not evidence or not evidence.get("observation_id"):
                continue
            await self.db.soar_executions.update_one(
                {"id": doc["payload"]["execution_id"]},
                {"$addToSet": {"response_evidence_refs": {
                    "technique_id": doc["technique_id"],
                    "source_event_id": doc["source_event_id"],
                    "observation_id": evidence["observation_id"],
                }}},
            )
        return result

    async def ingest_ml_predictions(
        self,
        *,
        prediction_id: str | None = None,
        entity_type: str | None = None,
        technique_id: str | None = None,
        limit: int = 250,
    ) -> dict[str, int | bool]:
        query: dict[str, Any] = {}
        if prediction_id:
            query["prediction_id"] = str(prediction_id).strip()
        if entity_type:
            query["entity_type"] = str(entity_type).strip()

        predictions = await self.db.ml_predictions.find(query).limit(limit).to_list(length=limit)
        docs: list[dict[str, Any]] = []
        for prediction in predictions:
            docs.extend(
                ml_prediction_to_integration_evidence(
                    prediction,
                    technique_id=technique_id,
                )
            )

        return await self._insert_integration_docs(docs, limit=limit)

    async def ingest_honeytoken_accesses(
        self,
        *,
        token_id: str | None = None,
        technique_id: str | None = None,
        trigger_soar: bool = False,
        limit: int = 250,
    ) -> dict[str, int | bool]:
        query: dict[str, Any] = {}
        if token_id:
            query["token_id"] = str(token_id).strip()

        accesses = await self.db.honey_token_accesses.find(query).limit(limit).to_list(length=limit)
        docs: list[dict[str, Any]] = []
        source_by_event_id: dict[str, dict[str, Any]] = {}
        for access in accesses:
            doc = honeytoken_access_to_integration_evidence(
                access,
                technique_id=technique_id,
            )
            if doc is None:
                continue
            docs.append(doc)
            source_by_event_id[doc["source_event_id"]] = access

        result = await self._insert_integration_docs(docs, limit=limit)
        result["soar_triggered"] = 0
        result["soar_evidence_claimed"] = 0
        result["soar_evidence_linked"] = 0

        for doc in docs:
            evidence = await self.db.integration_evidence.find_one({
                "source_kind": "integration_evidence",
                "source_event_id": doc["source_event_id"],
            })
            if not evidence:
                continue
            source = source_by_event_id.get(doc["source_event_id"]) or {}
            update = {
                "world_fanout_status": evidence.get("world_fanout_status"),
                "observation_id": evidence.get("observation_id"),
                "source_event_id": doc["source_event_id"],
            }
            await self.db.honey_token_accesses.update_one(
                {"id": source.get("id") or source.get("access_id")},
                {"$set": update},
            )

            if trigger_soar and evidence.get("observation_id"):
                try:
                    from backend.soar_engine import SOAREngine

                    event = {
                        "trigger_type": "deception_token_access",
                        "severity": doc.get("severity") or "critical",
                        "token_id": doc["payload"].get("token_id"),
                        "token_name": doc["payload"].get("token_name"),
                        "token_type": doc["payload"].get("token_type"),
                        "access_id": doc["payload"].get("access_id"),
                        "source_ip": doc["payload"].get("source_ip"),
                        "host_id": doc["payload"].get("source_ip"),
                        "session_id": doc["payload"].get("deception_case_id"),
                        "deception_case_id": doc["payload"].get("deception_case_id"),
                        "deception_event_id": doc["payload"].get("deception_event_id"),
                        "observation_id": evidence.get("observation_id"),
                        "source_event_id": doc["source_event_id"],
                        "mitre_techniques": [doc["technique_id"]],
                    }
                    executions = await SOAREngine().trigger_playbooks(event, db=self.db)
                    result["soar_triggered"] = int(result["soar_triggered"]) + len(executions)
                    for execution in executions:
                        handoff = await self.ingest_soar_executions(
                            execution_id=execution.id,
                            limit=limit,
                        )
                        result["soar_evidence_claimed"] = (
                            int(result["soar_evidence_claimed"])
                            + int(handoff["claimed"])
                        )
                        persisted_execution = await self.db.soar_executions.find_one({
                            "id": execution.id,
                        })
                        result["soar_evidence_linked"] = (
                            int(result["soar_evidence_linked"])
                            + len((persisted_execution or {}).get("response_evidence_refs") or [])
                        )
                except Exception:
                    logger.exception("Honeytoken SOAR trigger failed")
                    result["failed"] = int(result["failed"]) + 1

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
