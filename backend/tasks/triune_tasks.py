from celery_app import celery_app
from services.world_model import WorldModelService
from triune import MetatronService

# simple periodic metatron tick task
@celery_app.task(name="backend.tasks.triune_tasks.metatron_tick")
async def metatron_tick():
    # world_model and metatron_service import through server to avoid circular import
    from backend.server import db
    world = WorldModelService(db)
    metatron = MetatronService(db)
    return await metatron.tick()


# Loki ingestion task (sync Celery task that runs async world model operations)
@celery_app.task(name="backend.tasks.triune_tasks.loki_ingest")
def loki_ingest(payload: dict):
    """Process an ingestion payload from Loki (or other collectors) into the world model.

    This is a synchronous Celery task that delegates to the async WorldModelService methods.
    """
    import asyncio
    from backend.server import db
    from services.world_model import WorldEntity, WorldEdge, EntityType
    import uuid
    from datetime import datetime, timezone

    wm = WorldModelService(db)

    async def _process():
        kind = payload.get("kind") or payload.get("type")
        if not kind:
            return {"error": "missing kind"}
        if kind in ("detection", "entity", "alert", "file"):
            eid = payload.get("id") or str(uuid.uuid4())
            ent_type = payload.get("entity_type") or payload.get("type") or "detection"
            try:
                et = EntityType(ent_type)
            except Exception:
                et = EntityType.detection
            attrs = payload.get("attributes", {}) or {}
            ent = WorldEntity(id=eid, type=et, attributes=attrs)
            await wm.upsert_entity(ent)
            return {"status": "ok", "id": eid}
        if kind == "edge":
            src = payload.get("source")
            tgt = payload.get("target")
            rel = payload.get("relation", "related_to")
            if not src or not tgt:
                return {"error": "edge requires source and target"}
            edge = WorldEdge(source=src, target=tgt, relation=rel, created=datetime.now(timezone.utc))
            await wm.add_edge(edge)
            return {"status": "ok"}
        if kind == "campaign":
            cid = payload.get("id") or str(uuid.uuid4())
            attrs = payload.get("attributes", {}) or {}
            ent = WorldEntity(id=cid, type=EntityType.campaign, attributes=attrs)
            await wm.upsert_entity(ent)
            return {"status": "ok", "id": cid}
        return {"error": f"unsupported kind: {kind}"}

    return asyncio.run(_process())


@celery_app.task(name="backend.tasks.triune_tasks.michael_analyze")
def michael_analyze(entity_ids: list = None):
    """Background analysis task that asks Michael to score/rank candidate responses and persists results."""
    import asyncio
    from backend.server import db
    from triune import MichaelService
    from services.world_model import WorldModelService
    from datetime import datetime, timezone
    import uuid

    wm = WorldModelService(db)
    michael = MichaelService(db)

    async def _run():
        if entity_ids:
            candidates = []
            for eid in entity_ids:
                doc = await wm.entities.find_one({"id": eid}, {"_id": 0})
                if doc:
                    attrs = doc.get("attributes", {})
                    candidates.append(attrs.get("suggested_action") or f"investigate:{eid}")
        else:
            actions = await wm.list_actions(limit=20)
            candidates = [f"{a['action']}:{a['entity_id']}" for a in actions]

        ranked = await michael.rank_responses(candidates)
        # persist results for dashboard / Metatron consumption
        doc = {
            "id": str(uuid.uuid4()),
            "created": datetime.now(timezone.utc),
            "entities": entity_ids or [],
            "candidates": candidates,
            "ranked": ranked,
        }
        try:
            await db.triune_analysis.insert_one(doc)
        except Exception:
            # best-effort: ignore persistence errors
            pass
        return {"id": doc["id"], "ranked_count": len(ranked)}

    return asyncio.run(_run())
