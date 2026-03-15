from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import secrets
import logging

try:
    from services.world_events import emit_world_event
except Exception:
    try:
        from backend.services.world_events import emit_world_event
    except Exception:
        emit_world_event = None

logger = logging.getLogger(__name__)


class OutboundGateService:
    """Central outbound gating service for all high-impact actions."""

    def __init__(self, db: Any):
        self.db = db

    async def gate_action(
        self,
        *,
        action_type: str,
        actor: str,
        payload: Dict[str, Any],
        impact_level: str = "high",
        subject_id: Optional[str] = None,
        entity_refs: Optional[List[str]] = None,
        requires_triune: bool = True,
    ) -> Dict[str, Any]:
        """Queue an action for triune approval and return queue metadata."""
        now = datetime.now(timezone.utc).isoformat()
        queue_id = secrets.token_hex(8)
        decision_id = secrets.token_hex(8)
        action_id = payload.get("command_id") or payload.get("action_id") or secrets.token_hex(8)

        refs = [r for r in (entity_refs or []) if r]
        if subject_id:
            refs.insert(0, subject_id)

        queue_doc = {
            "queue_id": queue_id,
            "action_id": action_id,
            "action_type": action_type,
            "subject_id": subject_id,
            "actor": actor,
            "impact_level": impact_level,
            "payload": payload,
            "status": "pending",
            "created_at": now,
            "updated_at": now,
        }

        decision_doc = {
            "decision_id": decision_id,
            "related_queue_id": queue_id,
            "action_id": action_id,
            "action_type": action_type,
            "subject_id": subject_id,
            "actor": actor,
            "status": "pending",
            "created_at": now,
            "updated_at": now,
            "notes": f"Queued for triune approval: {action_type}",
        }

        try:
            await self.db.triune_outbound_queue.insert_one(queue_doc)
            await self.db.triune_decisions.insert_one(decision_doc)
        except Exception as e:
            logger.exception("Failed to gate outbound action '%s': %s", action_type, e)
            raise

        if emit_world_event is not None and self.db is not None:
            try:
                await emit_world_event(
                    self.db,
                    event_type="outbound_gate_action_queued",
                    entity_refs=refs + [action_id, queue_id, decision_id],
                    payload={
                        "status": "pending",
                        "action_type": action_type,
                        "impact_level": impact_level,
                        "actor": actor,
                    },
                    trigger_triune=requires_triune,
                )
            except Exception:
                pass

        return {
            "status": "queued",
            "action_id": action_id,
            "queue_id": queue_id,
            "decision_id": decision_id,
            "action_type": action_type,
            "impact_level": impact_level,
            "message": "Action queued for triune approval",
        }

    async def enqueue_command_for_approval(self, agent_id: str, command: Dict) -> Dict[str, Any]:
        """Backward-compatible wrapper for legacy command gating."""
        return await self.gate_action(
            action_type="agent_command",
            actor="system",
            payload=command,
            impact_level="high",
            subject_id=agent_id,
            entity_refs=[command.get("command_id")],
            requires_triune=True,
        )
