from fastapi import APIRouter
from typing import Any
from datetime import datetime, timezone

try:
    from services.world_model import WorldModelService
except Exception:
    from backend.services.world_model import WorldModelService

router = APIRouter()

class MetatronService:
    def __init__(self, db: Any = None):
        self.db = db
        if db is not None:
            self.entities = db.world_entities
            self.edges = db.world_edges
            self.campaigns = db.campaigns

    def set_database(self, db: Any):
        """Set Mongo database instance for service."""
        self.__init__(db)

    async def tick(self) -> dict:
        """Perform periodic reasoning cycle (stub)."""
        if self.db is None:
            return {"error": "database not configured"}
        count = await self.entities.count_documents({})
        return {"entities": count}

    async def assess_world_state(self, snapshot: dict, event_type: str = "unknown", context: dict | None = None) -> dict:
        """Produce a structured strategic judgment from canonical world state.

        This keeps Metatron focused on *meaning/judgment* from state snapshots,
        not raw collection concerns.
        """
        context = context or {}
        if self.db is None:
            return {
                "status": "degraded",
                "reason": "database not configured",
                "event_type": event_type,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        wm = WorldModelService(self.db)
        hotspots = await wm.list_hotspots(limit=5)
        actions = await wm.list_actions(limit=5)
        timeline = await wm.list_timeline(limit=10)

        hotspot_docs = [h.model_dump() if hasattr(h, "model_dump") else h.dict() for h in hotspots]
        max_risk = max([float((h.get("attributes") or {}).get("risk_score") or 0.0) for h in hotspot_docs] + [0.0])
        confidence = max(0.2, min(0.98, 0.3 + (0.5 * max_risk)))

        campaigns = []
        for doc in (snapshot.get("entities") or []):
            if str(doc.get("type") or "") == "campaign":
                campaigns.append({
                    "id": doc.get("id"),
                    "name": (doc.get("attributes") or {}).get("name"),
                    "stage": (doc.get("attributes") or {}).get("stage"),
                    "confidence": (doc.get("attributes") or {}).get("confidence", confidence),
                })

        return {
            "status": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "context": context,
            "environment_state": {
                "entity_count": snapshot.get("entity_count", 0),
                "top_risky_entities": hotspot_docs,
                "timeline_window": timeline,
            },
            "campaign_narratives": campaigns,
            "predicted_next_sectors": ["identity", "endpoint", "network"] if max_risk >= 0.5 else ["monitoring"],
            "recommended_response_posture": "containment_ready" if max_risk >= 0.7 else "elevated_monitoring",
            "approval_tier_suggestion": "high" if max_risk >= 0.8 else ("medium" if max_risk >= 0.5 else "low"),
            "confidence": round(confidence, 4),
            "recommended_actions": actions,
        }

@router.get("/metatron/hello")
async def hello():
    return {"msg": "Metatron is alive"}

@router.get("/metatron/tick")
async def tick():
    # import here to avoid circular dependencies
    from backend.triune.metatron import MetatronService
    from backend.server import db
    service = MetatronService(db)
    result = await service.tick()
    return result
