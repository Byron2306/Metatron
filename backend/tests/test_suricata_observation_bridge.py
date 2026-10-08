"""Suricata source-native classification and historical-boundary gates."""
import pytest

from observation_db_helpers import Database
from backend.services.observation_fabric import ObservationStore


def evidence(**changes):
    doc = dict(schema="seraph.suricata.alert.v1", witness="suricata",
               source_event_type="alert", source_event_id="eve-001",
               timestamp="2026-10-08T12:00:00Z", flow_id=44,
               interface="eth0", direction="to_server", src_ip="172.28.0.4",
               src_port=49152, dst_ip="172.28.0.5", dst_port=443, protocol="TCP",
               action="allowed", signature_id=123, signature="Native signature",
               category="Native category", severity=2,
               metadata={"confidence": ["High"]}, provenance="suricata_eve_alert",
               reconciliation_scope="network_alert", world_fanout_status="pending")
    doc.update(changes)
    return doc


def test_suricata_alert_maps_without_flattening_native_classification():
    from backend.services.observation_fabric import suricata_alert_to_observation
    obs = suricata_alert_to_observation(evidence())
    assert obs.witness == "suricata"
    assert obs.source_kind == "network_ids"
    assert obs.source_event_type == "alert"
    assert obs.source_event_id == "eve-001"
    assert obs.entity_refs == ["ip:172.28.0.4", "ip:172.28.0.5"]
    assert obs.native_severity == 2
    assert obs.native_confidence is None
    assert obs.payload["metadata"] == {"confidence": ["High"]}
    assert obs.payload["signature_id"] == 123
    assert obs.payload["category"] == "Native category"
    assert obs.payload["interface"] == "eth0"
    assert obs.payload["direction"] == "to_server"
    assert "techniques" not in obs.payload
    assert "world_fanout_status" not in obs.payload


@pytest.mark.asyncio
async def test_suricata_adapter_does_not_promote_historical_unmarked_alerts():
    from backend.services.observation_fabric import SuricataObservationBridge
    db = Database()
    doc = evidence()
    del doc["world_fanout_status"]
    await db.suricata_alert_evidence.insert_one(doc)
    result = await SuricataObservationBridge(db).claim_pending()
    assert result["claimed"] == 0
    assert await db.canonical_observations.count_documents({}) == 0


@pytest.mark.asyncio
async def test_suricata_bridge_claims_only_pending_evidence():
    from backend.services.observation_fabric import SuricataObservationBridge
    db = Database()
    await ObservationStore(db).ensure_indexes()
    await db.suricata_alert_evidence.insert_one(evidence())
    await db.suricata_alert_evidence.insert_one(evidence(source_event_id="old", world_fanout_status="emitted"))
    await db.suricata_alert_evidence.insert_one(evidence(source_event_id="other", witness="zeek"))
    result = await SuricataObservationBridge(db).claim_pending()
    assert result["claimed"] == 1
    doc = await db.suricata_alert_evidence.find_one({"source_event_id": "eve-001"})
    assert doc["world_fanout_status"] == "observed"
    assert doc["observation_id"].startswith("obs-")


@pytest.mark.asyncio
async def test_suricata_bridge_reconciles_existing_observation_after_restart():
    from backend.services.observation_fabric import SuricataObservationBridge, suricata_alert_to_observation
    db = Database()
    await ObservationStore(db).ensure_indexes()
    await ObservationStore(db).claim(suricata_alert_to_observation(evidence()))
    await db.suricata_alert_evidence.insert_one(evidence())
    result = await SuricataObservationBridge(db).claim_pending()
    assert result["reconciled"] == 1
    assert await db.canonical_observations.count_documents({}) == 1
    assert (await db.suricata_alert_evidence.find_one({"source_event_id": "eve-001"}))["world_fanout_status"] == "reconciled"


@pytest.mark.asyncio
async def test_suricata_adapter_rejects_missing_source_event_id_without_marking_emitted():
    from backend.services.observation_fabric import SuricataObservationBridge
    db = Database()
    await db.suricata_alert_evidence.insert_one(evidence(source_event_id=None))
    result = await SuricataObservationBridge(db).claim_pending()
    assert result["failed"] == 1
    assert (await db.suricata_alert_evidence.find_one({}))["world_fanout_status"] == "pending"
    assert await db.canonical_observations.count_documents({}) == 0
