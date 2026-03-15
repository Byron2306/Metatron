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


IMPACT_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
MANDATORY_HIGH_IMPACT_ACTIONS = {
    "response_execution",
    "response_block_ip",
    "response_unblock_ip",
    "swarm_command",
    "agent_command",
    "cross_sector_hardening",
    "quarantine_restore",
    "quarantine_delete",
    "quarantine_agent",
    "tool_execution",
    "mcp_tool_execution",
}


class OutboundGateService:
    """Central outbound gate used before high-impact action execution."""

    def __init__(self, db: Any):
        self.db = db

    @staticmethod
    def _normalize_impact(impact_level: str) -> str:
        normalized = str(impact_level or "high").lower().strip()
        return normalized if normalized in IMPACT_ORDER else "high"

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
        """Queue action for approval. Mandatory for high-impact action types."""
        normalized_action = str(action_type or "unknown").strip().lower()
        normalized_impact = self._normalize_impact(impact_level)

        # Governance hardening: these paths cannot skip triune and cannot be low impact.
        if normalized_action in MANDATORY_HIGH_IMPACT_ACTIONS:
            requires_triune = True
            if IMPACT_ORDER[normalized_impact] < IMPACT_ORDER["high"]:
                normalized_impact = "high"

        now = datetime.now(timezone.utc).isoformat()
        queue_id = secrets.token_hex(8)
        decision_id = secrets.token_hex(8)
        action_id = payload.get("command_id") or payload.get("action_id") or secrets.token_hex(8)

        refs = [r for r in (entity_refs or []) if r]
        if subject_id and subject_id not in refs:
            refs.insert(0, subject_id)

        queue_doc = {
            "queue_id": queue_id,
            "action_id": action_id,
            "action_type": normalized_action,
            "subject_id": subject_id,
            "actor": actor,
            "impact_level": normalized_impact,
            "payload": payload,
            "status": "pending",
            "created_at": now,
            "updated_at": now,
        }

        decision_doc = {
            "decision_id": decision_id,
            "related_queue_id": queue_id,
            "action_id": action_id,
            "action_type": normalized_action,
            "subject_id": subject_id,
            "actor": actor,
            "status": "pending",
            "created_at": now,
            "updated_at": now,
            "notes": f"Queued for triune approval: {normalized_action}",
        }

        try:
            await self.db.triune_outbound_queue.insert_one(queue_doc)
            await self.db.triune_decisions.insert_one(decision_doc)
        except Exception as exc:
            logger.exception("Failed to gate outbound action '%s': %s", normalized_action, exc)
            raise

        if emit_world_event is not None and self.db is not None:
            try:
                await emit_world_event(
                    self.db,
                    event_type="outbound_gate_action_queued",
                    entity_refs=refs + [action_id, queue_id, decision_id],
                    payload={
                        "status": "pending",
                        "action_type": normalized_action,
                        "impact_level": normalized_impact,
                        "actor": actor,
                    },
                    trigger_triune=requires_triune,
                    source="outbound_gate",
                )
            except Exception:
                logger.debug("World event emit failed for queued outbound action", exc_info=True)

        return {
            "status": "queued",
            "action_id": action_id,
            "queue_id": queue_id,
            "decision_id": decision_id,
            "action_type": normalized_action,
            "impact_level": normalized_impact,
            "message": "Action queued for triune approval",
        }

    async def enqueue_command_for_approval(self, agent_id: str, command: Dict[str, Any]) -> Dict[str, Any]:
        """Backward-compatible command-gating wrapper."""
        return await self.gate_action(
            action_type="agent_command",
            actor="system",
            payload=command,
            impact_level="high",
            subject_id=agent_id,
            entity_refs=[agent_id, command.get("command_id")],
            requires_triune=True,
        )
