import pytest

from observation_db_helpers import Database
from backend.services.observation_fabric import ObservationStore


@pytest.mark.asyncio
async def test_osquery_catalog_ingest_persists_and_claims_docs(tmp_path):
    from backend.services.integration_observation_fabric import IntegrationObservationBridge

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
    },
    {
      "name": "t1105_socket",
      "description": "Ingress Tool Transfer socket activity",
      "attack_techniques": ["T1105"],
      "query": "SELECT * FROM process_open_sockets;"
    }
  ]
}
""")

    result = await IntegrationObservationBridge(db).ingest_osquery_catalog(
        catalog,
        timestamp="2026-10-09T07:10:00+00:00",
    )

    assert result["ingested"] is True
    assert result["loaded"] == 2
    assert result["inserted"] == 2
    assert result["claimed"] == 2
    assert result["failed"] == 0
    assert await db.integration_evidence.count_documents({}) == 2
    assert await db.canonical_observations.count_documents({
        "source_event_type": "osquery_query_catalog",
    }) == 2


@pytest.mark.asyncio
async def test_osquery_catalog_ingest_is_idempotent(tmp_path):
    from backend.services.integration_observation_fabric import IntegrationObservationBridge

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

    first = await IntegrationObservationBridge(db).ingest_osquery_catalog(
        catalog,
        timestamp="2026-10-09T07:10:00+00:00",
    )
    second = await IntegrationObservationBridge(db).ingest_osquery_catalog(
        catalog,
        timestamp="2026-10-09T07:10:00+00:00",
    )

    assert first["inserted"] == 1
    assert second["inserted"] == 0
    assert second["duplicates"] == 1
    assert second["claimed"] == 0
    assert second["reconciled"] == 0
    assert await db.integration_evidence.count_documents({}) == 1
    assert await db.canonical_observations.count_documents({}) == 1
