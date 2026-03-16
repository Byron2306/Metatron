from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

try:
    from services.triune_orchestrator import TriuneOrchestrator
except Exception:
    from backend.services.triune_orchestrator import TriuneOrchestrator


EVENT_CLASS_PASSIVE_FACT = "passive_fact"
EVENT_CLASS_LOCAL_REFLEX = "local_reflex"
EVENT_CLASS_STRATEGIC_RECOMPUTE = "strategic_recompute"
EVENT_CLASS_ACTION_CRITICAL_RECOMPUTE = "action_critical_recompute"

_ACTION_CRITICAL_MARKERS = (
    "outbound_gate",
    "boundary_crossing",
    "gated",
    "approval",
    "command_created",
    "command_queued",
    "tool_execution",
    "quarantine_",
    "cross_sector",
    "response_block",
    "response_unblock",
)

_STRATEGIC_MARKERS = (
    "deception_interaction",
    "beacon",
    "campaign",
    "threat",
    "detection",
    "risk",
    "triune_periodic_tick",
)

_LOCAL_REFLEX_MARKERS = (
    "heartbeat",
    "telemetry",
    "acknowledged",
    "status_update",
    "settings_updated",
)


def classify_event_type(event_type: str, payload: Optional[Dict[str, Any]] = None) -> str:
    """Classify event into persistence class independent of trigger policy."""
    et = str(event_type or "").lower().strip()
    payload = payload or {}

    if any(marker in et for marker in _ACTION_CRITICAL_MARKERS):
        return EVENT_CLASS_ACTION_CRITICAL_RECOMPUTE
    if any(marker in et for marker in _STRATEGIC_MARKERS):
        return EVENT_CLASS_STRATEGIC_RECOMPUTE
    if any(marker in et for marker in _LOCAL_REFLEX_MARKERS):
        return EVENT_CLASS_LOCAL_REFLEX

    if payload.get("impact_level") in {"high", "critical"}:
        return EVENT_CLASS_ACTION_CRITICAL_RECOMPUTE
    if payload.get("risk_delta") or payload.get("predicted_next_sectors"):
        return EVENT_CLASS_STRATEGIC_RECOMPUTE

    # Keep default behavior close to historic "trigger by default".
    return EVENT_CLASS_STRATEGIC_RECOMPUTE


def should_trigger_triune(event_class: str) -> bool:
    return event_class in {
        EVENT_CLASS_STRATEGIC_RECOMPUTE,
        EVENT_CLASS_ACTION_CRITICAL_RECOMPUTE,
    }


async def emit_world_event(
    db: Any,
    event_type: str,
    entity_refs: Optional[List[str]] = None,
    payload: Optional[Dict[str, Any]] = None,
    trigger_triune: Optional[bool] = None,
    source: Optional[str] = None,
    event_class: Optional[str] = None,
) -> Dict[str, Any]:
    """Persist a canonical world event and optionally execute Triune recomputation.

    This helper keeps routers/tasks from hand-rolling event persistence and
    direct Metatron/Michael/Loki wiring.
    """

    entity_refs = entity_refs or []
    payload = payload or {}

    resolved_event_class = event_class or classify_event_type(event_type, payload)
    resolved_trigger_triune = should_trigger_triune(resolved_event_class) if trigger_triune is None else bool(trigger_triune)

    event = {
        "id": f"wevt-{uuid.uuid4().hex[:12]}",
        "type": event_type,
        "event_class": resolved_event_class,
        "entity_refs": entity_refs,
        "payload": payload,
        "source": source or "world_event_emitter",
        "triune_triggered": resolved_trigger_triune,
        "created": datetime.now(timezone.utc).isoformat(),
    }

    if db is not None and hasattr(db, "world_events"):
        try:
            await db.world_events.insert_one(event)
        except Exception:
            # best-effort persistence
            pass

    triune_bundle = None
    if resolved_trigger_triune:
        orchestrator = TriuneOrchestrator(db)
        triune_bundle = await orchestrator.handle_world_change(
            event_type=event_type,
            entity_ids=entity_refs,
            context={
                "source": source or "world_event_emitter",
                "payload": payload,
                "event_class": resolved_event_class,
            },
        )

    return {"event": event, "triune": triune_bundle}
