from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from services.outbound_gate import OutboundGateService
except Exception:
    from backend.services.outbound_gate import OutboundGateService

try:
    from services.world_events import emit_world_event
except Exception:
    try:
        from backend.services.world_events import emit_world_event
    except Exception:
        emit_world_event = None


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class GovernedDispatchService:
    """Shared command dispatch service for all governed queue writes."""

    def __init__(self, db: Any):
        self.db = db
        self.gate = OutboundGateService(db)

    async def queue_gated_agent_command(
        self,
        *,
        action_type: str,
        actor: str,
        agent_id: str,
        command_doc: Dict[str, Any],
        impact_level: str = "high",
        entity_refs: Optional[List[str]] = None,
        requires_triune: bool = True,
        event_type: Optional[str] = None,
        event_payload: Optional[Dict[str, Any]] = None,
        event_entity_refs: Optional[List[str]] = None,
        event_trigger_triune: bool = True,
    ) -> Dict[str, Any]:
        """Gate and persist a command in agent_commands with uniform metadata."""
        queued = await self.gate.gate_action(
            action_type=action_type,
            actor=actor,
            payload=command_doc,
            impact_level=impact_level,
            subject_id=agent_id,
            entity_refs=entity_refs or [agent_id, command_doc.get("command_id")],
            requires_triune=requires_triune,
        )

        now = _iso_now()
        persisted = dict(command_doc)
        persisted.setdefault("agent_id", agent_id)
        persisted.setdefault("created_at", now)
        persisted["updated_at"] = now
        persisted["status"] = "gated_pending_approval"
        persisted.setdefault("state_version", 1)
        if not persisted.get("state_transition_log"):
            persisted["state_transition_log"] = [
                {
                    "from_status": None,
                    "to_status": "gated_pending_approval",
                    "actor": actor or "unknown",
                    "reason": "queued for triune approval",
                    "timestamp": now,
                }
            ]
        persisted["queue_id"] = queued.get("queue_id")
        persisted["decision_id"] = queued.get("decision_id")
        persisted["decision_context"] = {
            "decision_id": queued.get("decision_id"),
            "queue_id": queued.get("queue_id"),
            "approved": False,
            "released_to_execution": False,
        }
        if "authority_context" not in persisted:
            persisted["authority_context"] = {
                "principal": actor,
                "capability": persisted.get("command_type"),
                "token_id": (persisted.get("parameters") or {}).get("token_id"),
                "scope": {"zone_from": "governance", "zone_to": "agent_control_zone"},
                "contract_version": "endpoint-boundary.v1",
            }
        persisted["gate"] = {
            "queue_id": queued.get("queue_id"),
            "decision_id": queued.get("decision_id"),
            "action_id": queued.get("action_id"),
        }

        await self.db.agent_commands.insert_one(persisted)

        if event_type and emit_world_event is not None:
            await emit_world_event(
                self.db,
                event_type=event_type,
                entity_refs=event_entity_refs or [agent_id, persisted.get("command_id")],
                payload=event_payload or {},
                trigger_triune=event_trigger_triune,
            )

        return {"queued": queued, "command": persisted}

    async def enqueue_command_delivery(
        self,
        *,
        command_id: str,
        agent_id: str,
        command_type: str,
        parameters: Optional[Dict[str, Any]] = None,
        actor: str = "system",
        status: str = "pending",
        decision_id: Optional[str] = None,
        queue_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Insert into command_queue via one shared helper."""
        now = _iso_now()
        queue_doc: Dict[str, Any] = {
            "command_id": command_id,
            "agent_id": agent_id,
            "command_type": command_type,
            "parameters": parameters or {},
            "status": status,
            "created_at": now,
            "created_by": actor,
        }
        if decision_id:
            queue_doc["decision_id"] = decision_id
        if queue_id:
            queue_doc["outbound_queue_id"] = queue_id
        if metadata:
            queue_doc["metadata"] = metadata

        await self.db.command_queue.insert_one(queue_doc)

        if emit_world_event is not None:
            await emit_world_event(
                self.db,
                event_type="command_delivery_queued",
                entity_refs=[agent_id, command_id],
                payload={
                    "command_type": command_type,
                    "decision_id": decision_id,
                    "queue_id": queue_id,
                },
                trigger_triune=False,
                source="governed_dispatch",
            )

        return queue_doc
