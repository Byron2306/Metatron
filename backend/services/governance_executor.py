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

    @staticmethod
    def _governance_context_for_execution(
        *,
        decision_id: str,
        queue_id: str,
        action_type: str,
    ) -> Dict[str, Any]:
        return {
            "approved": True,
            "decision_id": decision_id,
            "queue_id": queue_id,
            "action_type": action_type,
        }

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

        if action_type == "cross_sector_hardening":
            operation = str(payload.get("operation") or "").strip().lower()
            if operation in {"issue_token", "revoke_token", "revoke_principal_tokens"}:
                return await self._execute_token_operation(
                    decision=decision,
                    queue_doc=queue_doc,
                    payload=payload,
                    operation=operation,
                    actor=actor,
                )

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

    async def _execute_token_operation(
        self,
        *,
        decision: Dict[str, Any],
        queue_doc: Dict[str, Any],
        payload: Dict[str, Any],
        operation: str,
        actor: str,
    ) -> Dict[str, Any]:
        decision_id = decision.get("decision_id")
        related_queue_id = queue_doc.get("queue_id")
        action_type = str(queue_doc.get("action_type") or "").lower()
        now = _iso_now()
        governance_context = self._governance_context_for_execution(
            decision_id=decision_id,
            queue_id=related_queue_id,
            action_type=action_type,
        )
        try:
            try:
                from services.token_broker import token_broker
            except Exception:
                from backend.services.token_broker import token_broker

            op_result: Dict[str, Any]
            if operation == "issue_token":
                principal = str(payload.get("principal") or "").strip()
                principal_identity = str(payload.get("principal_identity") or "").strip()
                requested_action = str(payload.get("action") or "").strip()
                targets = list(payload.get("targets") or [])
                if not principal or not principal_identity or not requested_action or not targets:
                    raise ValueError(
                        "issue_token requires principal, principal_identity, action, and non-empty targets"
                    )
                token = token_broker.issue_token(
                    principal=principal,
                    principal_identity=principal_identity,
                    action=requested_action,
                    targets=targets,
                    tool_id=payload.get("tool_id"),
                    ttl_seconds=int(payload.get("ttl_seconds") or 300),
                    max_uses=int(payload.get("max_uses") or 1),
                    constraints=payload.get("constraints") or {},
                    governance_context=governance_context,
                    issued_by=actor,
                )
                op_result = {
                    "operation": operation,
                    "token_id": token.token_id,
                    "principal": token.principal,
                    "expires_at": token.expires_at,
                    "max_uses": token.max_uses,
                }
            elif operation == "revoke_token":
                token_id = str(payload.get("token_id") or "")
                if not token_id:
                    raise ValueError("Missing token_id for revoke_token")
                token_broker.revoke_token(
                    token_id,
                    governance_context=governance_context,
                    revoked_by=actor,
                )
                op_result = {"operation": operation, "token_id": token_id, "revoked": True}
            elif operation == "revoke_principal_tokens":
                principal = str(payload.get("principal") or "")
                if not principal:
                    raise ValueError("Missing principal for revoke_principal_tokens")
                revoked_count = token_broker.revoke_tokens_for_principal(
                    principal,
                    governance_context=governance_context,
                    revoked_by=actor,
                )
                op_result = {
                    "operation": operation,
                    "principal": principal,
                    "revoked_count": int(revoked_count),
                }
            else:
                raise ValueError(f"Unsupported token operation: {operation}")

            await self.db.triune_outbound_queue.update_one(
                {"queue_id": related_queue_id},
                {
                    "$set": {
                        "status": "released_to_execution",
                        "released_at": now,
                        "updated_at": now,
                        "execution_result": op_result,
                    }
                },
            )
            await self.db.triune_decisions.update_one(
                {"decision_id": decision_id},
                {
                    "$set": {
                        "execution_status": "executed",
                        "executed_at": now,
                        "updated_at": now,
                        "execution_result": op_result,
                    }
                },
            )
            if emit_world_event is not None:
                await emit_world_event(
                    self.db,
                    event_type="governance_token_operation_executed",
                    entity_refs=[decision_id, related_queue_id, operation],
                    payload=op_result,
                    trigger_triune=False,
                    source="governance_executor",
                )
            return {"outcome": "executed", "result": op_result}
        except Exception as exc:
            logger.exception("Failed token operation '%s' for decision %s: %s", operation, decision_id, exc)
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
            await self.db.triune_outbound_queue.update_one(
                {"queue_id": related_queue_id},
                {
                    "$set": {
                        "status": "approved_execution_failed",
                        "updated_at": _iso_now(),
                    }
                },
            )
            return {"outcome": "failed", "reason": "token_operation_exception"}


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
