import pytest

from observation_db_helpers import Database
from backend.services.observation_fabric import ObservationStore


def ml_prediction():
    return {
        "prediction_id": "pred-001",
        "timestamp": "2026-10-11T14:08:00+00:00",
        "entity_type": "network",
        "entity_id": "203.0.113.77",
        "predicted_category": "data_exfiltration",
        "risk_level": "high",
        "confidence": 0.91,
        "threat_score": 87,
        "features": {"anomaly_score": 0.94},
        "contributing_factors": ["bytes_out: 120.00"],
        "recommended_actions": ["Block outbound connections"],
        "mitre_mappings": [
            {"tactic": "Exfiltration", "technique": "T1041", "name": "Exfiltration Over C2"},
        ],
    }


def test_ml_prediction_maps_to_integration_evidence():
    from backend.services.integration_observation_fabric import (
        ml_prediction_to_integration_evidence,
    )

    docs = ml_prediction_to_integration_evidence(ml_prediction())

    assert len(docs) == 1
    doc = docs[0]
    assert doc["schema"] == "seraph.integration.evidence.v1"
    assert doc["integration_name"] == "ml"
    assert doc["evidence_type"] == "ml_prediction"
    assert doc["technique_id"] == "T1041"
    assert doc["timestamp"] == "2026-10-11T14:08:00+00:00"
    assert doc["source_event_id"] == "ml|ml_prediction|T1041|pred-001"
    assert doc["severity"] == "high"
    assert doc["confidence"] == 0.91
    assert doc["payload"]["prediction_id"] == "pred-001"
    assert doc["payload"]["entity_id"] == "203.0.113.77"


@pytest.mark.asyncio
async def test_ml_predictions_ingest_and_claim_canonical_observation():
    from backend.services.integration_observation_fabric import IntegrationObservationBridge

    db = Database()
    await ObservationStore(db).ensure_indexes()
    await db.ml_predictions.insert_one(ml_prediction())

    result = await IntegrationObservationBridge(db).ingest_ml_predictions()

    source = await db.integration_evidence.find_one({"integration_name": "ml"})
    obs = await db.canonical_observations.find_one({"source_event_type": "ml_prediction"})

    assert result["inserted"] == 1
    assert result["claimed"] == 1
    assert source["world_fanout_status"] == "observed"
    assert obs["source_event_id"] == "ml|ml_prediction|T1041|pred-001"
    assert obs["entity_refs"] == ["mitre:T1041"]
    assert obs["native_severity"] == "high"
    assert obs["native_confidence"] == 0.91


@pytest.mark.asyncio
async def test_cognition_snapshot_links_ml_prediction_canonical_observations():
    from backend.services.cognition_fabric import CognitionFabricService
    from backend.services.integration_observation_fabric import IntegrationObservationBridge

    db = Database()
    await ObservationStore(db).ensure_indexes()
    await db.ml_predictions.insert_one(ml_prediction())
    await IntegrationObservationBridge(db).ingest_ml_predictions()

    snapshot = await CognitionFabricService(db).build_cognition_snapshot(
        world_snapshot={"entities": [{"id": "203.0.113.77", "type": "host"}]},
        event_type="ml_handoff_test",
        entity_ids=["203.0.113.77"],
        context={},
    )

    assert snapshot["ml"]["recent_prediction_count"] == 1
    assert snapshot["ml"]["canonical_observation_count"] == 1
    assert snapshot["ml"]["canonical_observation_ids"]
