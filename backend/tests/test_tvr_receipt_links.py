import pytest
from test_observation_fabric import Database

from backend.services.integration_observation_fabric import (
    tvr_record_to_integration_evidence,
)


def linked_tvr_record():
    return {
        "record_type": "technique_validation_record",
        "schema_version": "1.0.0",
        "validation_id": "TVR-T1059-2026-04-27-001",
        "technique": {"attack_id": "T1059", "name": "Command and Scripting Interpreter"},
        "procedure": {
            "procedure_id": "ART-T1059-1",
            "source": "atomic_red_team",
            "test_ref": "atomics/T1059/T1059.yaml#test-1",
        },
        "execution": {
            "started_at": "2026-04-27T10:00:00+00:00",
            "ended_at": "2026-04-27T10:01:00+00:00",
            "executor": "atomic_red_team",
            "status": "completed",
            "exit_code": 0,
            "run_ids": ["run-a", "run-b"],
            "job_ids": ["gha-linux-sweep-run1"],
            "runs": [
                {
                    "run_id": "run-a",
                    "job_id": "gha-linux-sweep-run1",
                    "stdout_sha256": "stdout-hash-a",
                    "exit_code": 0,
                    "finished_at": "2026-04-27T10:01:00+00:00",
                },
                {
                    "run_id": "run-b",
                    "job_id": "gha-linux-sweep-run1",
                    "stdout_sha256": "stdout-hash-b",
                    "exit_code": 0,
                    "finished_at": "2026-04-27T10:01:30+00:00",
                },
            ],
        },
        "analytic_evidence": {
            "osquery": [
                {
                    "query_id": "osq-t1059-processes",
                    "name": "t1059_process_exec",
                    "query_text": "SELECT pid, name, cmdline FROM processes;",
                    "result_count": 2,
                    "supporting_event_ids": ["agent-event-1", "agent-event-2"],
                }
            ],
            "sigma": [
                {
                    "rule_id": "sigma-rule-001",
                    "rule_sha256": "sigma-hash-001",
                    "title": "Suspicious command execution",
                    "detection_basis": "rule_fired_against_osquery_telemetry",
                    "supporting_event_ids": ["agent-event-1"],
                }
            ],
        },
        "host_telemetry_evidence": {
            "agent_id": "agent-001",
            "node_id": "node-001",
            "hostname": "debian",
            "supporting_event_ids": ["agent-event-1"],
        },
        "network_telemetry_evidence": {
            "zeek_uids": ["CZEEK1"],
            "arkime_session_ids": ["arkime-session-1"],
            "suricata_source_event_ids": ["flow-1|9900001|2026-04-27T10:00:00+00:00"],
        },
        "artifact_evidence": {
            "files": [
                {
                    "path": "/tmp/payload.sh",
                    "hashes": {"sha256": "file-sha-001"},
                }
            ]
        },
        "response_evidence": {
            "actions": [
                {
                    "action_id": "quarantine-001",
                    "action": "quarantine",
                    "status": "simulated",
                }
            ]
        },
        "correlation": {
            "anchors": {
                "event_ids": ["agent-event-1", "agent-event-2"],
                "host_ids": ["node-001"],
                "ip_addresses": ["192.0.2.10"],
                "process_ids": [1234],
            }
        },
        "quality": {"analyst_reviewed": True},
        "integrity": {"record_sha256": "tvr-sha-001"},
    }


def test_tvr_record_carries_receipt_links_for_evidence_graph():
    doc = tvr_record_to_integration_evidence(linked_tvr_record())

    links = doc["payload"]["receipt_links"]

    assert links["atomic"]["run_ids"] == ["run-a", "run-b"]
    assert links["atomic"]["job_ids"] == ["gha-linux-sweep-run1"]
    assert links["atomic"]["stdout_sha256"] == ["stdout-hash-a", "stdout-hash-b"]

    assert links["osquery"] == [
        {
            "query_id": "osq-t1059-processes",
            "name": "t1059_process_exec",
            "supporting_event_ids": ["agent-event-1", "agent-event-2"],
            "result_count": 2,
        }
    ]

    assert links["sigma"] == [
        {
            "rule_id": "sigma-rule-001",
            "rule_sha256": "sigma-hash-001",
            "supporting_event_ids": ["agent-event-1"],
            "detection_basis": "rule_fired_against_osquery_telemetry",
        }
    ]

    assert links["host"]["agent_id"] == "agent-001"
    assert links["host"]["node_id"] == "node-001"
    assert links["network"]["zeek_uids"] == ["CZEEK1"]
    assert links["network"]["arkime_session_ids"] == ["arkime-session-1"]
    assert links["network"]["suricata_source_event_ids"] == [
        "flow-1|9900001|2026-04-27T10:00:00+00:00"
    ]
    assert links["artifacts"]["file_sha256"] == ["file-sha-001"]
    assert links["response"]["action_ids"] == ["quarantine-001"]
    assert links["correlation"]["event_ids"] == ["agent-event-1", "agent-event-2"]


def test_tvr_receipt_links_are_empty_structures_when_sections_missing():
    minimal = {
        "record_type": "technique_validation_record",
        "schema_version": "1.0.0",
        "validation_id": "TVR-T1001-2026-04-27-002",
        "technique": {"attack_id": "T1001"},
        "execution": {"started_at": "2026-04-25T07:48:56.596336+00:00"},
        "integrity": {},
    }

    doc = tvr_record_to_integration_evidence(minimal)
    links = doc["payload"]["receipt_links"]

    assert links["atomic"] == {"run_ids": [], "job_ids": [], "stdout_sha256": []}
    assert links["osquery"] == []
    assert links["sigma"] == []
    assert links["host"] == {}
    assert links["network"] == {}
    assert links["artifacts"] == {"paths": [], "file_sha256": []}
    assert links["response"] == {"action_ids": []}
    assert links["correlation"] == {}

@pytest.mark.asyncio
async def test_tvr_receipt_links_resolve_to_canonical_observation_refs():
    from backend.services.integration_observation_fabric import (
        resolve_tvr_receipt_observation_refs,
        tvr_record_to_integration_evidence,
    )

    db = Database()

    await db.canonical_observations.insert_many([
        {
            "schema": "seraph.observation.v1",
            "observation_id": "obs-osquery-001",
            "witness": "integration_evidence",
            "source_kind": "integration_evidence",
            "source_event_type": "osquery_query_catalog",
            "source_event_id": "osquery|osquery_query_catalog|T1001|t1001_c2_sockets|2026-10-09T07:00:00+00:00",
            "observed_at": "2026-10-09T07:00:00+00:00",
            "ingested_at": "2026-10-09T07:00:00+00:00",
            "entity_refs": ["mitre:T1001"],
            "reconciliation_scope": "integration_evidence",
            "native_severity": None,
            "native_confidence": None,
            "provenance": "osquery_catalog",
            "evidence_digest": "digest-osquery",
            "payload": {
                "integration_name": "osquery",
                "evidence_type": "osquery_query_catalog",
                "technique_id": "T1001",
                "payload": {"query_name": "t1001_c2_sockets"},
            },
            "promotion_state": "pending",
        },
        {
            "schema": "seraph.observation.v1",
            "observation_id": "obs-sigma-001",
            "witness": "integration_evidence",
            "source_kind": "integration_evidence",
            "source_event_type": "sigma_rule_match",
            "source_event_id": "sigma|sigma_rule_match|T1001|2026-10-09T07:00:00+00:00",
            "observed_at": "2026-10-09T07:00:00+00:00",
            "ingested_at": "2026-10-09T07:00:00+00:00",
            "entity_refs": ["mitre:T1001"],
            "reconciliation_scope": "integration_evidence",
            "native_severity": None,
            "native_confidence": None,
            "provenance": "sigma",
            "evidence_digest": "digest-sigma",
            "payload": {
                "integration_name": "sigma",
                "evidence_type": "sigma_rule_match",
                "technique_id": "T1001",
                "payload": {"rule_id": "sigma-rule-001"},
            },
            "promotion_state": "pending",
        },
        {
            "schema": "seraph.observation.v1",
            "observation_id": "obs-atomic-001",
            "witness": "integration_evidence",
            "source_kind": "integration_evidence",
            "source_event_type": "atomic_stdout",
            "source_event_id": "atomic_red_team|atomic_stdout|TVR-T1001-2026-04-27-002|run-001|digest",
            "observed_at": "2026-10-09T07:00:00+00:00",
            "ingested_at": "2026-10-09T07:00:00+00:00",
            "entity_refs": ["mitre:T1001"],
            "reconciliation_scope": "integration_evidence",
            "native_severity": None,
            "native_confidence": None,
            "provenance": "atomic_red_team",
            "evidence_digest": "digest-atomic",
            "payload": {
                "integration_name": "atomic_red_team",
                "evidence_type": "atomic_stdout",
                "technique_id": "T1001",
                "payload": {
                    "validation_id": "TVR-T1001-2026-04-27-002",
                    "run_id": "run-001",
                },
            },
            "promotion_state": "pending",
        },
    ])

    record = linked_tvr_record()
    record["validation_id"] = "TVR-T1001-2026-04-27-002"
    record["technique"] = {"attack_id": "T1001", "name": "Data Obfuscation"}

    # Normalize the receipt links to the seeded observation documents.
    record.setdefault("execution", {})["runs"] = [{"run_id": "run-001"}]
    record["osquery"] = [{"query_name": "t1001_c2_sockets"}]
    record["sigma"] = [{"rule_id": "sigma-rule-001"}]

    doc = tvr_record_to_integration_evidence(record)
    doc["payload"]["receipt_links"] = {
        "atomic": [{"run_id": "run-001"}],
        "osquery": [{"query_name": "t1001_c2_sockets"}],
        "sigma": [{"rule_id": "sigma-rule-001"}],
    }

    refs = await resolve_tvr_receipt_observation_refs(db, doc)

    assert refs["schema"] == "seraph.tvr.evidence_graph_refs.v1"
    assert refs["validation_id"] == "TVR-T1001-2026-04-27-002"
    assert refs["technique_id"] == "T1001"
    assert refs["resolved_observation_ids"] == [
        "obs-atomic-001",
        "obs-osquery-001",
        "obs-sigma-001",
    ]
    assert refs["missing_links"] == []

