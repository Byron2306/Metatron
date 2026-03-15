from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    from services.world_events import emit_world_event
except Exception:
    try:
        from backend.services.world_events import emit_world_event
    except Exception:
        emit_world_event = None


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class GovernanceDecisionAuthority:
    """Canonical transition service for triune decision authority state."""

    def __init__(self, db: Any):
        self.db = db

    async def approve_decision(
        self,
        *,
        decision_id: str,
        actor: str,
        notes: Optional[str] = None,
        execution_status: str = "pending_executor",
        source: str = "governance_authority",
    ) -> Dict[str, Any]:
        decision = await self.db.triune_decisions.find_one({"decision_id": decision_id}, {"_id": 0})
        if not decision:
            return {"found": False, "decision_id": decision_id}

        now = _iso_now()
        related_queue_id = decision.get("related_queue_id")
        resolved_execution_status = execution_status if related_queue_id else "policy_only"
        await self.db.triune_decisions.update_one(
            {"decision_id": decision_id},
            {
                "$set": {
                    "status": "approved",
                    "approved_by": actor,
                    "approved_at": now,
                    "updated_at": now,
                    "execution_status": resolved_execution_status,
                    "approval_notes": notes,
                }
            },
        )
        if related_queue_id:
            await self.db.triune_outbound_queue.update_one(
                {"queue_id": related_queue_id},
                {
                    "$set": {
                        "status": "approved",
                        "approved_by": actor,
                        "approved_at": now,
                        "updated_at": now,
                        "execution_status": resolved_execution_status,
                    }
                },
            )

        # Mirror policy state when this decision originated from policy evaluation.
        await self.db.policy_decisions.update_one(
            {"decision_id": decision_id},
            {
                "$set": {
                    "status": "approved",
                    "approved_by": actor,
                    "approved_at": now,
                    "updated_at": now,
                    "approval_notes": notes,
                }
            },
        )

        if emit_world_event is not None:
            await emit_world_event(
                self.db,
                event_type="governance_decision_approved",
                entity_refs=[decision_id, related_queue_id],
                payload={"actor": actor, "notes": notes, "source": source},
                trigger_triune=False,
                source=source,
            )

        return {
            "found": True,
            "decision_id": decision_id,
            "related_queue_id": related_queue_id,
            "execution_status": resolved_execution_status,
        }

    async def deny_decision(
        self,
        *,
        decision_id: str,
        actor: str,
        reason: Optional[str] = None,
        source: str = "governance_authority",
    ) -> Dict[str, Any]:
        decision = await self.db.triune_decisions.find_one({"decision_id": decision_id}, {"_id": 0})
        if not decision:
            return {"found": False, "decision_id": decision_id}

        now = _iso_now()
        related_queue_id = decision.get("related_queue_id")
        await self.db.triune_decisions.update_one(
            {"decision_id": decision_id},
            {
                "$set": {
                    "status": "denied",
                    "denied_by": actor,
                    "denied_at": now,
                    "updated_at": now,
                    "execution_status": "skipped",
                    "denial_reason": reason,
                }
            },
        )
        if related_queue_id:
            await self.db.triune_outbound_queue.update_one(
                {"queue_id": related_queue_id},
                {
                    "$set": {
                        "status": "denied",
                        "denied_by": actor,
                        "denied_at": now,
                        "updated_at": now,
                        "execution_status": "skipped",
                    }
                },
            )

        await self.db.policy_decisions.update_one(
            {"decision_id": decision_id},
            {
                "$set": {
                    "status": "denied",
                    "denied_by": actor,
                    "denied_at": now,
                    "updated_at": now,
                    "denial_reason": reason,
                }
            },
        )

        if emit_world_event is not None:
            await emit_world_event(
                self.db,
                event_type="governance_decision_denied",
                entity_refs=[decision_id, related_queue_id],
                payload={"actor": actor, "reason": reason, "source": source},
                trigger_triune=False,
                source=source,
            )

        return {
            "found": True,
            "decision_id": decision_id,
            "related_queue_id": related_queue_id,
            "execution_status": "skipped",
        }
