from pathlib import Path

import pytest

from observation_db_helpers import Database
from backend.services.observation_fabric import ObservationStore


def test_osquery_catalog_entry_maps_to_integration_evidence():
    from backend.services.integration_observation_fabric import (
        osquery_catalog_entry_to_integration_evidence,
    )

    item = {
        "name": "t1059_process_exec",
        "description": "Process execution for Command and Scripting Interpreter",
        "attack_techniques": ["T1059"],
        "query": "SELECT pid, name, cmdline FROM processes;",
    }

    doc = osquery_catalog_entry_to_integration_evidence(
        item,
        technique_id="T1059",
        timestamp="2026-10-09T07:00:00+00:00",
    )

    assert doc["schema"] == "seraph.integration.evidence.v1"
    assert doc["source_kind"] == "integration_evidence"
    assert doc["integration_name"] == "osquery"
    assert doc["evidence_type"] == "osquery_query_catalog"
    assert doc["technique_id"] == "T1059"
    assert doc["timestamp"] == "2026-10-09T07:00:00+00:00"
    assert doc["world_fanout_status"] == "pending"
    assert doc["payload"]["query_name"] == "t1059_process_exec"
    assert doc["payload"]["query"] == "SELECT pid, name, cmdline FROM processes;"
    assert doc["payload"]["attack_techniques"] == ["T1059"]


def test_osquery_catalog_loader_emits_one_doc_per_query_technique(tmp_path):
    from backend.services.integration_observation_fabric import (
        load_osquery_catalog_integration_evidence,
    )

    catalog = tmp_path / "osquery.json"
    catalog.write_text("""
{
  "schema_version": "1",
  "queries": [
    {
      "name": "multi",
      "description": "Multi technique query",
      "attack_techniques": ["T1059", "T1105"],
      "query": "SELECT * FROM processes;"
    },
    {
      "name": "missing_attack",
      "description": "No mapped technique",
      "query": "SELECT * FROM users;"
    }
  ]
}
""")

    docs = load_osquery_catalog_integration_evidence(
        catalog,
        timestamp="2026-10-09T07:00:00+00:00",
    )

    assert [doc["technique_id"] for doc in docs] == ["T1059", "T1105"]
    assert all(doc["integration_name"] == "osquery" for doc in docs)
    assert all(doc["evidence_type"] == "osquery_query_catalog" for doc in docs)


@pytest.mark.asyncio
async def test_osquery_catalog_docs_claim_into_canonical_observations(tmp_path):
    from backend.services.integration_observation_fabric import (
        IntegrationObservationBridge,
        load_osquery_catalog_integration_evidence,
    )

    db = Database()
    await ObservationStore(db).ensure_indexes()

    catalog = tmp_path / "osquery.json"
    catalog.write_text("""
{
  "queries": [
    {
      "name": "t1059_process_exec",
      "description": "Process execution for Command and Scripting Interpreter",
      "attack_techniques": ["T1059"],
      "query": "SELECT pid, name, cmdline FROM processes;"
    }
  ]
}
""")

    docs = load_osquery_catalog_integration_evidence(
        catalog,
        timestamp="2026-10-09T07:00:00+00:00",
    )
    await db.integration_evidence.insert_many(docs)

    result = await IntegrationObservationBridge(db).claim_pending()

    obs = await db.canonical_observations.find_one({"witness": "integration_evidence"})
    source = await db.integration_evidence.find_one({"technique_id": "T1059"})

    assert result == {"claimed": 1, "reconciled": 0, "failed": 0}
    assert source["world_fanout_status"] == "observed"
    assert obs["source_event_type"] == "osquery_query_catalog"
    assert obs["entity_refs"] == ["mitre:T1059"]
    assert obs["payload"]["payload"]["query_name"] == "t1059_process_exec"
