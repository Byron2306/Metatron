"""Suricata source-native classification and historical-boundary gates."""
import pytest
import json
import importlib
from pathlib import Path

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


def eve_alert(timestamp="2026-10-08T12:00:00Z", severity=2):
    return {"event_type": "alert", "timestamp": timestamp, "flow_id": 44,
            "in_iface": "eth0", "direction": "to_server",
            "src_ip": "172.28.0.4", "src_port": 49152,
            "dest_ip": "172.28.0.5", "dest_port": 443, "proto": "TCP",
            "alert": {"action": "allowed", "signature_id": 123,
                      "signature": "Native signature", "category": "Native category",
                      "severity": severity, "metadata": {"confidence": ["High"]}}}


async def call_ingest(db, tmp_path, monkeypatch, events):
    # Real native reader + real route; a new sensor models a process restart.
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]))
    native = importlib.import_module("services.vns")
    route = importlib.import_module("backend.routers.advanced")
    monkeypatch.setattr(native.VirtualNetworkSensor, "_instance", None)
    sensor = native.VirtualNetworkSensor()
    sensor.db = db
    monkeypatch.setattr(native, "vns", sensor)
    monkeypatch.setattr(route, "get_db", lambda: db)
    path = tmp_path / "eve.json"
    path.write_text("\n".join(json.dumps(event) for event in events))
    monkeypatch.setenv("SURICATA_EVE_PATH", str(path))
    return await route.ingest_suricata_vns(force=True, current_user={"role": "admin"})


@pytest.mark.asyncio
async def test_suricata_ingest_drains_only_new_pending_alerts(tmp_path, monkeypatch):
    db = Database()
    await ObservationStore(db).ensure_indexes()
    result = await call_ingest(db, tmp_path, monkeypatch, [eve_alert()])
    assert result["record_errors"] == 0
    assert result["alerts_added"] == 1
    fabric = result["observation_fabric"]
    assert fabric["claimed"] == 1
    assert fabric["promoted"] == 1
    assert fabric["projected"] == 1
    assert fabric["failed"] == 0
    assert await db.vns_flows.count_documents({}) == 0
    assert await db.world_events.count_documents({}) == 1


@pytest.mark.asyncio
async def test_suricata_ingest_repeat_does_not_duplicate_world_event(tmp_path, monkeypatch):
    db = Database()
    await ObservationStore(db).ensure_indexes()
    await call_ingest(db, tmp_path, monkeypatch, [eve_alert()])
    replay = await call_ingest(db, tmp_path, monkeypatch, [eve_alert()])
    assert replay["observation_fabric"]["projected"] == 0
    repeated = await call_ingest(db, tmp_path, monkeypatch, [eve_alert(timestamp="2026-10-08T13:00:00Z")])
    assert repeated["observation_fabric"]["retained_without_promotion"] == 1
    assert await db.world_events.count_documents({}) == 1
    assert await db.canonical_observations.count_documents({}) == 2


@pytest.mark.asyncio
async def test_suricata_ingest_historical_alerts_are_not_backfilled(tmp_path, monkeypatch):
    db = Database()
    old = evidence(source_event_id="44|123|2026-10-08T12:00:00Z")
    del old["world_fanout_status"]
    await db.suricata_alert_evidence.insert_one(old)
    await ObservationStore(db).ensure_indexes()
    result = await call_ingest(db, tmp_path, monkeypatch, [eve_alert()])
    assert result["observation_fabric"]["claimed"] == 0
    assert await db.world_events.count_documents({}) == 0
    assert "observation_id" not in await db.suricata_alert_evidence.find_one({})


@pytest.mark.asyncio
async def test_suricata_ingest_projection_failure_leaves_retryable_state(tmp_path, monkeypatch):
    db = Database()
    await ObservationStore(db).ensure_indexes()
    db.world_events.failure = RuntimeError("Mongo event write unavailable")
    result = await call_ingest(db, tmp_path, monkeypatch, [eve_alert()])
    assert result["observation_fabric"]["failed"] == 1, result
    assert result["observation_fabric"]["projected"] == 0
    assert (await db.canonical_observations.find_one({}))["promotion_state"] == "pending"
    db.world_events.failure = None
    replay = await call_ingest(db, tmp_path, monkeypatch, [eve_alert()])
    assert replay["observation_fabric"]["projected"] == 1
    assert await db.world_events.count_documents({}) == 1


@pytest.mark.asyncio
async def test_suricata_ingest_reports_triune_disabled(tmp_path, monkeypatch):
    db = Database()
    await ObservationStore(db).ensure_indexes()
    result = await call_ingest(db, tmp_path, monkeypatch, [eve_alert()])
    assert result["observation_fabric"]["triune_triggered"] is False
