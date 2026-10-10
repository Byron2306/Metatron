import pytest

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
