import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    from services.governed_dispatch import GovernedDispatchService
except Exception:
    from backend.services.governed_dispatch import GovernedDispatchService

try:
    from services.world_events import emit_world_event
except Exception:
    try:
        from backend.services.world_events import emit_world_event
    except Exception:
        emit_world_event = None

logger = logging.getLogger(__name__)

_governance_executor_task: Optional[asyncio.Task] = None


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class GovernanceExecutorService:
    """Executes approved triune decisions into operational command queues."""

    DISPATCHABLE_ACTIONS = {
        "agent_command",
        "swarm_command",
        "response_execution",
        "cross_sector_hardening",
    }

    def __init__(self, db: Any):
        self.db = db
        self.dispatch = GovernedDispatchService(db)

    async def process_approved_decisions(self, *, limit: int = 100) -> Dict[str, Any]:
        cursor = self.db.triune_decisions.find(
            {
                "status": "approved",
                "related_queue_id": {"$exists": True, "$ne": None},
                "execution_status": {"$nin": ["executed", "skipped", "failed"]},
            },
            {"_id": 0},
        ).sort("updated_at", 1).limit(limit)
        decisions = await cursor.to_list(limit)

        processed = 0
        executed = 0
        skipped = 0
        failed = 0
        for decision in decisions:
            processed += 1
            result = await self._execute_decision(decision)
            outcome = result.get("outcome")
            if outcome == "executed":
                executed += 1
            elif outcome == "skipped":
                skipped += 1
            else:
                failed += 1

        return {
            "processed": processed,
            "executed": executed,
            "skipped": skipped,
            "failed": failed,
        }

    async def _execute_decision(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        decision_id = decision.get("decision_id")
        related_queue_id = decision.get("related_queue_id")
        now = _iso_now()

        queue_doc = await self.db.triune_outbound_queue.find_one(
            {"queue_id": related_queue_id},
            {"_id": 0},
        )
        if not queue_doc:
            await self.db.triune_decisions.update_one(
                {"decision_id": decision_id},
                {
                    "$set": {
                        "execution_status": "failed",
                        "execution_error": f"Queue document not found: {related_queue_id}",
                        "updated_at": now,
                    }
                },
            )
            return {"outcome": "failed", "reason": "queue_not_found"}

        action_type = str(queue_doc.get("action_type") or "").lower()
        payload = queue_doc.get("payload") or {}
        actor = queue_doc.get("actor") or "governance_executor"

        if action_type not in self.DISPATCHABLE_ACTIONS:
            await self.db.triune_outbound_queue.update_one(
                {"queue_id": related_queue_id},
                {"$set": {"status": "approved_no_executor", "updated_at": now}},
            )
            await self.db.triune_decisions.update_one(
                {"decision_id": decision_id},
                {"$set": {"execution_status": "skipped", "updated_at": now}},
            )
            if emit_world_event is not None:
                await emit_world_event(
                    self.db,
                    event_type="governance_executor_handler_missing",
                    entity_refs=[decision_id, related_queue_id, action_type],
                    payload={"action_type": action_type},
                    trigger_triune=False,
                    source="governance_executor",
                )
            return {"outcome": "skipped", "reason": "unsupported_action_type"}

        agent_id = queue_doc.get("subject_id") or payload.get("agent_id")
        command_id = payload.get("command_id") or queue_doc.get("action_id")
        command_type = (
            payload.get("command_type")
            or payload.get("type")
            or payload.get("operation")
            or action_type
        )
        parameters = payload.get("parameters") or payload.get("params") or payload.get("payload") or {}

        if not agent_id or not command_id:
            await self.db.triune_decisions.update_one(
                {"decision_id": decision_id},
                {
                    "$set": {
                        "execution_status": "failed",
                        "execution_error": "missing agent_id or command_id in approved payload",
                        "updated_at": now,
                    }
                },
            )
            return {"outcome": "failed", "reason": "missing_agent_or_command"}

        try:
            await self.dispatch.enqueue_command_delivery(
                command_id=command_id,
                agent_id=agent_id,
                command_type=command_type,
                parameters=parameters,
                actor=actor,
                decision_id=decision_id,
                queue_id=related_queue_id,
                metadata={"action_type": action_type, "source": "governance_executor"},
            )

            await self.db.agent_commands.update_many(
                {
                    "$or": [
                        {"decision_id": decision_id},
                        {"command_id": command_id},
                    ]
                },
                {
                    "$set": {"status": "pending", "updated_at": now},
                    "$inc": {"state_version": 1},
                    "$push": {
                        "state_transition_log": {
                            "from_status": "gated_pending_approval",
                            "to_status": "pending",
                            "actor": "system:governance-executor",
                            "reason": "triune decision approved; released to command_queue",
                            "timestamp": now,
                            "metadata": {
                                "decision_id": decision_id,
                                "queue_id": related_queue_id,
                            },
                        }
                    },
                },
            )

            await self.db.triune_outbound_queue.update_one(
                {"queue_id": related_queue_id},
                {
                    "$set": {
                        "status": "released_to_execution",
                        "released_at": now,
                        "updated_at": now,
                    }
                },
            )
            await self.db.triune_decisions.update_one(
                {"decision_id": decision_id},
                {"$set": {"execution_status": "executed", "executed_at": now, "updated_at": now}},
            )
            if emit_world_event is not None:
                await emit_world_event(
                    self.db,
                    event_type="governance_decision_executed",
                    entity_refs=[decision_id, related_queue_id, agent_id, command_id],
                    payload={"action_type": action_type, "command_type": command_type},
                    trigger_triune=False,
                    source="governance_executor",
                )
            return {"outcome": "executed"}
        except Exception as exc:
            logger.exception("Failed to execute approved decision %s: %s", decision_id, exc)
            await self.db.triune_decisions.update_one(
                {"decision_id": decision_id},
                {
                    "$set": {
                        "execution_status": "failed",
                        "execution_error": str(exc),
                        "updated_at": _iso_now(),
                    }
                },
            )
            return {"outcome": "failed", "reason": "execution_exception"}


def _executor_enabled() -> bool:
    return os.environ.get("GOVERNANCE_EXECUTOR_ENABLED", "true").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _executor_interval_seconds() -> float:
    try:
        return max(1.0, float(os.environ.get("GOVERNANCE_EXECUTOR_INTERVAL_SECONDS", "5")))
    except Exception:
        return 5.0


async def _executor_loop(db: Any) -> None:
    svc = GovernanceExecutorService(db)
    interval = _executor_interval_seconds()
    logger.info("Governance executor loop started (interval=%ss)", interval)
    try:
        while True:
            try:
                result = await svc.process_approved_decisions(limit=100)
                if result.get("processed", 0) > 0:
                    logger.info("Governance executor cycle: %s", result)
            except Exception:
                logger.exception("Governance executor cycle failed")
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        logger.info("Governance executor loop stopped")
        raise


def start_governance_executor(db: Any) -> None:
    global _governance_executor_task
    if not _executor_enabled():
        logger.info("Governance executor disabled by env")
        return
    if _governance_executor_task is None or _governance_executor_task.done():
        _governance_executor_task = asyncio.create_task(_executor_loop(db))


async def stop_governance_executor() -> None:
    global _governance_executor_task
    if _governance_executor_task is None:
        return
    _governance_executor_task.cancel()
    try:
        await _governance_executor_task
    except asyncio.CancelledError:
        pass
    _governance_executor_task = None
