from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

try:
    from services.triune_orchestrator import TriuneOrchestrator
except Exception:
    from backend.services.triune_orchestrator import TriuneOrchestrator


async def emit_world_event(
    db: Any,
    event_type: str,
    entity_refs: Optional[List[str]] = None,
    payload: Optional[Dict[str, Any]] = None,
    trigger_triune: bool = True,
    source: Optional[str] = None,
) -> Dict[str, Any]:
    """Persist a canonical world event and optionally execute Triune recomputation.

    This helper keeps routers/tasks from hand-rolling event persistence and
    direct Metatron/Michael/Loki wiring.
    """

    entity_refs = entity_refs or []
    payload = payload or {}

    event = {
        "id": f"wevt-{uuid.uuid4().hex[:12]}",
        "type": event_type,
        "entity_refs": entity_refs,
        "payload": payload,
        "source": source or "world_event_emitter",
        "created": datetime.now(timezone.utc).isoformat(),
    }

    if db is not None and hasattr(db, "world_events"):
        try:
            await db.world_events.insert_one(event)
        except Exception:
            # best-effort persistence
            pass

    triune_bundle = None
    if trigger_triune:
        orchestrator = TriuneOrchestrator(db)
        triune_bundle = await orchestrator.handle_world_change(
            event_type=event_type,
            entity_ids=entity_refs,
            context={"source": source or "world_event_emitter", "payload": payload},
        )

    return {"event": event, "triune": triune_bundle}
