import pytest

from observation_db_helpers import Database


@pytest.mark.asyncio
async def test_technique_evidence_graph_groups_tvr_linked_observations():
    from backend.services.evidence_graph import build_technique_evidence_graph

    db = Database()

    await db.canonical_observations.insert_many([
        {
            "observation_id": "obs-atomic-001",
            "witness": "integration_evidence",
            "source_event_type": "atomic_stdout",
            "entity_refs": ["mitre:T1001"],
            "payload": {
                "technique_id": "T1001",
                "payload": {
                    "validation_id": "TVR-T1001-2026-04-27-002",
                    "run_id": "run-001",
                },
            },
        },
        {
            "observation_id": "obs-osquery-001",
            "witness": "integration_evidence",
            "source_event_type": "osquery_query_catalog",
            "entity_refs": ["mitre:T1001"],
            "payload": {
                "technique_id": "T1001",
                "payload": {"query_name": "t1001_c2_sockets"},
            },
        },
        {
            "observation_id": "obs-sigma-001",
            "witness": "integration_evidence",
            "source_event_type": "sigma_rule_match",
            "entity_refs": ["mitre:T1001"],
            "payload": {
                "technique_id": "T1001",
                "payload": {"rule_id": "sigma-rule-001"},
            },
        },
        {
            "observation_id": "obs-tvr-001",
            "witness": "integration_evidence",
            "source_event_type": "technique_validation_record",
            "entity_refs": ["mitre:T1001"],
            "payload": {
                "integration_name": "tvr",
                "technique_id": "T1001",
                "payload": {
                    "validation_id": "TVR-T1001-2026-04-27-002",
                    "evidence_graph_refs": {
                        "schema": "seraph.tvr.evidence_graph_refs.v1",
                        "validation_id": "TVR-T1001-2026-04-27-002",
                        "technique_id": "T1001",
                        "resolved_observation_ids": [
                            "obs-atomic-001",
                            "obs-osquery-001",
                            "obs-sigma-001",
                        ],
                        "missing_links": [],
                    },
                },
            },
        },
    ])

    await db.world_events.insert_one({
        "type": "observation_promoted",
        "payload": {
            "observation_id": "obs-tvr-001",
            "technique_id": "T1001",
        },
    })
    await db.world_entities.insert_one({
        "id": "alert-test",
        "type": "alert",
        "attributes": {
            "observation_id": "obs-tvr-001",
            "technique_id": "T1001",
        },
    })

    graph = await build_technique_evidence_graph(db, "t1001")

    assert graph["schema"] == "seraph.evidence_graph.technique.v1"
    assert graph["technique_id"] == "T1001"
    assert graph["canonical_observation_count"] == 4
    assert graph["resolved_observation_ids"] == [
        "obs-atomic-001",
        "obs-osquery-001",
        "obs-sigma-001",
    ]
    assert graph["missing_links"] == []
    assert [doc["observation_id"] for doc in graph["sources"]["tvr"]] == ["obs-tvr-001"]
    assert {doc["observation_id"] for doc in graph["linked_observations"]} == {
        "obs-atomic-001",
        "obs-osquery-001",
        "obs-sigma-001",
    }
    assert graph["world_events"][0]["payload"]["observation_id"] == "obs-tvr-001"
    assert graph["world_entities"][0]["attributes"]["observation_id"] == "obs-tvr-001"
