from fastapi import APIRouter, Depends, HTTPException
from typing import Optional, List, Dict, Any
from routers.dependencies import get_db
from services.world_model import WorldModelService
try:
    from services.governance_epoch import get_governance_epoch_service
except Exception:
    from backend.services.governance_epoch import get_governance_epoch_service
try:
    from schemas.triune_models import MetatronState
except Exception:
    MetatronState = None

router = APIRouter()

try:
    from bson import ObjectId  # type: ignore
except Exception:  # pragma: no cover
    ObjectId = None


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    if ObjectId is not None and isinstance(value, ObjectId):
        return str(value)
    return value

@router.get("/metatron/hello")
async def hello():
    return {"msg": "Metatron router active"}

@router.get("/metatron/entities/count")
async def entity_count(db=Depends(get_db)):
    """Return number of world-model entities (for smoke test)."""
    wm = WorldModelService(db)
    if not hasattr(wm, "entities") or wm.entities is None:
        # database not configured (e.g. during unit tests)
        return {"entity_count": 0}
    c = await wm.entities.count_documents({})
    return {"entity_count": c}

@router.get("/metatron/summary")
async def summary(db=Depends(get_db)):
    """Return a top-level world view summary (entity counts, campaigns)."""
    wm = WorldModelService(db)
    result: dict = {"entities": 0, "campaigns": []}
    if hasattr(wm, "entities") and wm.entities is not None:
        result["entities"] = await wm.entities.count_documents({})
    if hasattr(wm, "campaigns") and wm.campaigns is not None:
        cursor = wm.campaigns.find({}, {"_id": 0})
        result["campaigns"] = [c async for c in cursor]
    return _json_safe(result)


@router.get(
    "/metatron/state",
    responses={
        200: {
            "description": "Metatron state with triune analysis hints",
            "content": {
                "application/json": {
                    "example": {
                        "header": {"risk_level": "elevated", "active_campaigns": 1, "ml_confidence": 0.82},
                        "narrative": {"campaign_id": "camp-42", "objective": "exfiltrate-data"},
                        "attack_path": {"nodes": [{"id": "host1"}], "edges": [{"source": "host1", "target": "db1"}]},
                        "trust": {"identity": "degraded", "device": "compromised"},
                        "hotspots": [{"id": "host1", "risk": 0.92, "reason": "multiple suspicious processes"}],
                        "actions": [{"suggested": "isolate:host1", "reversibility": "manual"}],
                        "hypotheses": [
                            {"analysis_id": "a1", "candidate": "isolate:host1", "score": 0.92, "components": {"keyword": 0.9, "risk": 0.8, "ai": {"provider": "ollama", "explanation": "Isolation recommended due to high risk signals and active exfiltration indicators."}}}
                        ],
                        "timeline": [{"ts": "2026-03-11T10:00:00Z", "event": "suspicious_process_detected", "entity": "host1"}],
                        "triune_analyses": [
                            {
                                "id": "a1",
                                "created": "2026-03-11T10:01:00Z",
                                "entities": ["host1"],
                                "candidates": ["isolate:host1", "monitor:host1"],
                                "ranked": [
                                    {"candidate": "isolate:host1", "score": 0.92, "components": {"keyword": 0.9, "risk": 0.8, "recency": 0.95, "ai": {"provider": "ollama", "explanation": "Evidence of data exfiltration and high-risk behaviors; isolation minimizes blast radius to critical services."}}},
                                    {"candidate": "monitor:host1", "score": 0.45, "components": {"keyword": 0.2, "risk": 0.3, "ai": {"provider": "ollama", "explanation": "Monitoring preserves evidence but risks ongoing exfiltration."}}}
                                ]
                            }
                        ]
                    }
                }
            },
        }
    },
)
async def state(db=Depends(get_db)):
    """Return comprehensive metatron world-state for UI consumption."""
    wm = WorldModelService(db)
    epoch_service = get_governance_epoch_service(db)
    active_epoch = await epoch_service.get_active_epoch(scope="global")
    governance_context = wm.get_governance_placeholders() if hasattr(wm, "get_governance_placeholders") else {}
    if active_epoch is not None:
        if not governance_context.get("current_governance_epoch"):
            governance_context["current_governance_epoch"] = active_epoch.epoch_id
        if not governance_context.get("current_score_id"):
            governance_context["current_score_id"] = active_epoch.score_id
        if not governance_context.get("current_genre_mode"):
            governance_context["current_genre_mode"] = active_epoch.genre_mode
        if not governance_context.get("current_world_state_hash"):
            governance_context["current_world_state_hash"] = active_epoch.world_state_hash
        if not governance_context.get("strictness_level"):
            governance_context["strictness_level"] = active_epoch.strictness_level
    # header calculations (guard against missing DB)
    if hasattr(wm, "entities") and wm.entities is not None:
        total_entities = await wm.count_entities()
        total_campaigns = await wm.count_entities({"type": "campaign"})
        high_risk_identities = await wm.count_entities({"type": "user", "attributes.risk_score": {"$gte": 0.75}})
        critical_hosts = await wm.count_entities({"type": "host", "attributes.risk_score": {"$gte": 0.8}})
        active_containments = await wm.count_entities({"attributes.contained": True})
        deception_interactions = await wm.count_entities({"attributes.deception_hit": True})
    else:
        total_entities = total_campaigns = high_risk_identities = critical_hosts = active_containments = deception_interactions = 0
    hdr = {
        "risk_level": "elevated" if high_risk_identities + critical_hosts > 0 else "low",
        "active_campaigns": total_campaigns,
        "high_risk_identities": high_risk_identities,
        "critical_hosts": critical_hosts,
        "active_containments": active_containments,
        "deception_interactions": deception_interactions,
        "last_state_change": None,
        "newest_narrative": None,
        "trust_drift": "stable",
        "ml_confidence": 0.0,
        "score_id": governance_context.get("current_score_id"),
        "genre_mode": governance_context.get("current_genre_mode"),
        "governance_epoch": governance_context.get("current_governance_epoch"),
        "world_state_hash": governance_context.get("current_world_state_hash"),
        "strictness_level": governance_context.get("strictness_level"),
    }
    # threat narrative based on latest campaign
    if hasattr(wm, "campaigns") and wm.campaigns is not None:
        latest = await wm.get_latest_campaign()
    else:
        latest = None
    if latest:
        narr = {
            "campaign_id": latest.id,
            "stage": latest.attributes.get("stage") if hasattr(latest, "attributes") else None,
            "objective": latest.attributes.get("objective") if hasattr(latest, "attributes") else None,
            "origin_host": latest.attributes.get("origin_host") if hasattr(latest, "attributes") else None,
            "evidence": latest.attributes.get("evidence", []),
            "confidence": latest.confidence,
            "predicted_next": latest.attributes.get("predicted_next", []),
        }
    else:
        narr = {"campaign_id": None, "stage": None, "objective": None, "origin_host": None, "evidence": [], "confidence": 0.0, "predicted_next": []}
    # build attack path from world model if DB available
    if hasattr(wm, "entities") and wm.entities is not None:
        attack = await wm.compute_attack_path()
    else:
        attack = {"nodes": [], "edges": []}
    # trust state derived
    if hasattr(wm, "entities") and wm.entities is not None:
        trust = await wm.compute_trust_metrics()
    else:
        trust = {"identity": "stable", "device": "stable", "agent_health": "unknown", "policy_violations": 0, "token_anomalies": 0}
    # hotspots
    if hasattr(wm, "entities") and wm.entities is not None:
        hs_entities = await wm.list_hotspots(limit=5)
        hotspots = [e.dict() for e in hs_entities]
    else:
        hotspots = []
    # timeline, actions, hypotheses
    if hasattr(wm, "entities") and wm.entities is not None:
        timeline = await wm.list_timeline(limit=50)
        actions = await wm.list_actions(limit=10)
    else:
        timeline = []
        actions = []
    hypotheses = []

    # include recent triune analyses (background Michael results) for UI
    triune_analyses = []
    try:
        if hasattr(db, "triune_analysis") and db.triune_analysis is not None:
            cursor = db.triune_analysis.find({}, {"_id": 0}).sort("created", -1).limit(10)
            triune_analyses = [t async for t in cursor]
            # build simple hypotheses list from top-ranked candidate per analysis
            for t in triune_analyses:
                ranked = t.get("ranked") or []
                if ranked:
                    top = ranked[0]
                    # include ai components if present in ranked entries
                    hypotheses.append({
                        "analysis_id": t.get("id"),
                        "candidate": top.get("candidate") if isinstance(top, dict) else top,
                        "score": top.get("score") if isinstance(top, dict) else None,
                        "components": top.get("components") if isinstance(top, dict) else None,
                        "score_id": (
                            ((t.get("context") or {}).get("score_id"))
                            or (((t.get("context") or {}).get("polyphonic_context") or {}).get("score_id")
                                if isinstance((t.get("context") or {}).get("polyphonic_context"), dict) else None)
                            or governance_context.get("current_score_id")
                        ),
                        "genre_mode": (
                            ((t.get("context") or {}).get("genre_mode"))
                            or (((t.get("context") or {}).get("polyphonic_context") or {}).get("genre_mode")
                                if isinstance((t.get("context") or {}).get("polyphonic_context"), dict) else None)
                            or governance_context.get("current_genre_mode")
                        ),
                        "notation_token": (
                            ((t.get("context") or {}).get("notation_token"))
                            or (((t.get("context") or {}).get("polyphonic_context") or {}).get("notation_token")
                                if isinstance((t.get("context") or {}).get("polyphonic_context"), dict) else None)
                        ),
                        "world_state_hash": (
                            ((t.get("context") or {}).get("world_state_hash"))
                            or (((t.get("context") or {}).get("polyphonic_context") or {}).get("world_state_hash")
                                if isinstance((t.get("context") or {}).get("polyphonic_context"), dict) else None)
                            or governance_context.get("current_world_state_hash")
                        ),
                        "voice_role": (
                            ((t.get("context") or {}).get("voice_type"))
                            or ((((t.get("context") or {}).get("polyphonic_context") or {}).get("voice_profile") or {}).get("voice_type")
                                if isinstance((t.get("context") or {}).get("polyphonic_context"), dict) else None)
                        ),
                    })
    except Exception:
        # best-effort: do not fail the entire state response if triune collection is missing
        triune_analyses = []

    resp = {
        "header": hdr,
        "narrative": narr,
        "attack_path": attack,
        "trust": trust,
        "hotspots": hotspots,
        "actions": actions,
        "hypotheses": hypotheses,
        "triune_analyses": triune_analyses,
        "timeline": timeline,
        "governance_context": governance_context,
    }
    safe_resp = _json_safe(resp)

    # optionally validate/serialize via Pydantic model if available
    if MetatronState is not None:
        try:
            return MetatronState(**safe_resp)
        except Exception:
            # best-effort: fall back to plain dict
            pass
    return safe_resp

# additional endpoints will be added as architecture evolves


@router.get("/metatron/entity/{entity_id}")
async def get_entity(entity_id: str, db=Depends(get_db)):
    """Return a single world-model entity by id."""
    wm = WorldModelService(db)
    if not hasattr(wm, "entities") or wm.entities is None:
        raise HTTPException(status_code=404, detail="world model not available")
    doc = await wm.entities.find_one({"id": entity_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="entity not found")
    return _json_safe(doc)


@router.get("/metatron/entities")
async def list_entities(type: Optional[str] = None, limit: int = 50, db=Depends(get_db)):
    """List world-model entities, optional filter by `type` and limit."""
    wm = WorldModelService(db)
    if not hasattr(wm, "entities") or wm.entities is None:
        return []
    query = {}
    if type:
        query["type"] = type
    cursor = wm.entities.find(query, {"_id": 0}).limit(limit)
    results = [d async for d in cursor]
    return _json_safe(results)


@router.get("/metatron/metrics")
async def metatron_metrics(db=Depends(get_db)):
    """Return graph metrics computed from the world model."""
    wm = WorldModelService(db)
    if not hasattr(wm, "entities") or wm.entities is None:
        return {"centrality": {}, "avg_path_distance": 0.0, "privilege_escalation_likelihood": 0.0, "blast_radius": 0}
    metrics = await wm.compute_graph_metrics()
    return _json_safe(metrics)


@router.post("/metatron/campaign")
async def create_campaign(payload: Dict[str, Any], db=Depends(get_db)):
    """Create a campaign narrative object.

    Accepts keys: id (optional), name, objective, stage, confidence, entities, techniques, predicted_next, attributes
    """
    wm = WorldModelService(db)
    if not hasattr(wm, "campaigns") or wm.campaigns is None:
        raise HTTPException(status_code=500, detail="campaign storage not configured")
    import uuid
    from datetime import datetime, timezone

    cid = payload.get("id") or f"camp-{uuid.uuid4().hex[:8]}"
    # Build canonical campaign document with explicit fields
    doc = {
        "id": cid,
        "name": payload.get("name"),
        "techniques": payload.get("techniques") or [],
        "confidence": float(payload.get("confidence") or 0.0),
        "entities": payload.get("entities") or [],
        "objective": payload.get("objective"),
        "stage": payload.get("stage"),
        "predicted_next_moves": payload.get("predicted_next") or payload.get("predicted_next_moves") or [],
        "timeline": payload.get("timeline") or [],
        "attributes": payload.get("attributes") or {},
        "first_detected": payload.get("first_detected") or datetime.now(timezone.utc).isoformat(),
    }
    # Ensure attributes reflect key narrative fields for backward compatibility
    doc["attributes"].setdefault("objective", doc.get("objective"))
    doc["attributes"].setdefault("stage", doc.get("stage"))
    doc["attributes"].setdefault("predicted_next", doc.get("predicted_next_moves") or [])
    await wm.campaigns.insert_one(doc)
    # return created doc without _id
    out = {k: v for k, v in doc.items()}
    return _json_safe(out)


@router.get("/metatron/campaigns")
async def list_campaigns(db=Depends(get_db)):
    wm = WorldModelService(db)
    if not hasattr(wm, "campaigns") or wm.campaigns is None:
        return []
    cursor = wm.campaigns.find({}, {"_id": 0}).sort("first_detected", -1)
    return _json_safe([c async for c in cursor])


@router.get("/metatron/campaign/{campaign_id}")
async def get_campaign(campaign_id: str, db=Depends(get_db)):
    wm = WorldModelService(db)
    if not hasattr(wm, "campaigns") or wm.campaigns is None:
        raise HTTPException(status_code=404, detail="campaign storage not configured")
    doc = await wm.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="campaign not found")
    return _json_safe(doc)


@router.put("/metatron/campaign/{campaign_id}")
async def update_campaign(campaign_id: str, payload: Dict[str, Any], db=Depends(get_db)):
    wm = WorldModelService(db)
    if not hasattr(wm, "campaigns") or wm.campaigns is None:
        raise HTTPException(status_code=500, detail="campaign storage not configured")
    # merge provided fields into attributes and top-level
    to_set = {}
    if "name" in payload:
        to_set["name"] = payload["name"]
    if "techniques" in payload:
        to_set["techniques"] = payload["techniques"]
    if "confidence" in payload:
        try:
            to_set["confidence"] = float(payload["confidence"])
        except Exception:
            pass
    # attributes and top-level narrative fields
    attr_updates = payload.get("attributes") or {}
    # allow top-level objective/stage/predicted_next_moves/timeline as convenience
    for k in ("objective", "stage", "predicted_next", "predicted_next_moves", "origin_host", "evidence", "timeline"):
        if k in payload:
            # normalize predicted_next vs predicted_next_moves
            if k == "predicted_next_moves" and "predicted_next" not in attr_updates:
                attr_updates["predicted_next"] = payload[k]
            else:
                attr_updates[k] = payload[k]
    if attr_updates:
        to_set.setdefault("attributes", {})
        to_set["attributes"].update(attr_updates)
    # also allow updating explicit top-level fields
    if "objective" in payload:
        to_set["objective"] = payload["objective"]
    if "stage" in payload:
        to_set["stage"] = payload["stage"]
    if "predicted_next" in payload or "predicted_next_moves" in payload:
        to_set["predicted_next_moves"] = payload.get("predicted_next") or payload.get("predicted_next_moves")
    if "timeline" in payload:
        to_set["timeline"] = payload["timeline"]

    if not to_set:
        return {"updated": False}

    await wm.campaigns.update_one({"id": campaign_id}, {"$set": to_set}, upsert=False)
    doc = await wm.campaigns.find_one({"id": campaign_id}, {"_id": 0})
    return _json_safe(doc or {"updated": True})


@router.delete("/metatron/campaign/{campaign_id}")
async def delete_campaign(campaign_id: str, db=Depends(get_db)):
    wm = WorldModelService(db)
    if not hasattr(wm, "campaigns") or wm.campaigns is None:
        raise HTTPException(status_code=500, detail="campaign storage not configured")
    await wm.campaigns.delete_one({"id": campaign_id})
    return {"deleted": True}
