from typing import Any, Dict
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
    """Simple outbound gating service: persist outbound attempts and create a pending decision.

    The real Metatron decision lifecycle will later update the `triune_decisions`
    and the `triune_outbound_queue` documents. For now this helper centralizes
    queue writes so callers can opt into gating.
    """

    def __init__(self, db: Any):
        self.db = db

    async def enqueue_command_for_approval(self, agent_id: str, command: Dict) -> Dict:
        """Persist outbound command and create a triune decision in pending state.

        Returns a dict describing the queued outcome: {status, command_id, queue_id, decision_id}
        """
        command_id = command.get("command_id") or secrets.token_hex(8)
        now = datetime.now(timezone.utc).isoformat()

        queue_doc = {
            "queue_id": secrets.token_hex(8),
            "command_id": command_id,
            "agent_id": agent_id,
            "command": command,
            "status": "pending",
            "created_at": now,
            "updated_at": now,
        }

        decision_doc = {
            "decision_id": secrets.token_hex(8),
            "related_queue_id": queue_doc["queue_id"],
            "command_id": command_id,
            "agent_id": agent_id,
            "status": "pending",
            "created_at": now,
            "updated_at": now,
            "notes": "Queued for Metatron triune approval",
        }

        # Persist both documents transactionally if supported; best-effort insert otherwise
        try:
            await self.db.triune_outbound_queue.insert_one(queue_doc)
            await self.db.triune_decisions.insert_one(decision_doc)
        except Exception as e:
            logger.exception("Failed to enqueue outbound command for approval: %s", e)
            raise

        logger.info("Enqueued command %s for agent %s as queue=%s decision=%s", command_id, agent_id, queue_doc["queue_id"], decision_doc["decision_id"])

        if emit_world_event is not None and self.db is not None:
            try:
                await emit_world_event(
                    self.db,
                    event_type="outbound_gate_command_queued",
                    entity_refs=[agent_id, command_id, queue_doc["queue_id"], decision_doc["decision_id"]],
                    payload={"status": "pending"},
                    trigger_triune=True,
                )
            except Exception:
                pass

        return {
            "status": "queued",
            "command_id": command_id,
            "queue_id": queue_doc["queue_id"],
            "decision_id": decision_doc["decision_id"],
            "message": "Command queued for triune approval",
        }
