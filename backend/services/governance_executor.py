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

try:
    from services.telemetry_chain import tamper_evident_telemetry
except Exception:
    try:
        from backend.services.telemetry_chain import tamper_evident_telemetry
    except Exception:
        tamper_evident_telemetry = None

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
    DOMAIN_OPERATION_ACTIONS = {
        "response_block_ip",
        "response_unblock_ip",
        "quarantine_restore",
        "quarantine_delete",
        "quarantine_agent",
        "vpn_initialize",
        "vpn_start",
        "vpn_stop",
        "vpn_peer_add",
        "vpn_peer_remove",
        "vpn_kill_switch_enable",
        "vpn_kill_switch_disable",
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

    async def _emit_execution_completion_event(
        self,
        *,
        decision_id: Optional[str],
        queue_id: Optional[str],
        action_type: str,
        outcome: str,
        reason: Optional[str] = None,
        command_id: Optional[str] = None,
        command_type: Optional[str] = None,
        token_id: Optional[str] = None,
        execution_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        polyphonic_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        if emit_world_event is None:
            return
        resolved_polyphonic = polyphonic_context if isinstance(polyphonic_context, dict) else {}
        voice_profile = resolved_polyphonic.get("voice_profile") if isinstance(resolved_polyphonic.get("voice_profile"), dict) else {}
        refs = [r for r in [decision_id, queue_id, command_id, token_id, execution_id] if r]
        payload = {
            "decision_id": decision_id,
            "queue_id": queue_id,
            "action_type": action_type,
            "outcome": outcome,
            "reason": reason,
            "command_id": command_id,
            "command_type": command_type,
            "token_id": token_id,
            "execution_id": execution_id,
            "trace_id": trace_id,
            "polyphonic_context": resolved_polyphonic or None,
            "voice_type": voice_profile.get("voice_type"),
            "capability_class": voice_profile.get("capability_class"),
        }
        await emit_world_event(
            self.db,
            event_type="governance_execution_completed",
            entity_refs=refs,
            payload=payload,
            trigger_triune=outcome == "failed",
            source="governance_executor",
        )

    def _record_execution_audit(
        self,
        *,
        decision_id: Optional[str],
        queue_id: Optional[str],
        action_type: str,
        outcome: str,
        reason: Optional[str] = None,
        actor: Optional[str] = None,
        targets: Optional[list] = None,
        command_id: Optional[str] = None,
        command_type: Optional[str] = None,
        token_id: Optional[str] = None,
        execution_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        polyphonic_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        if tamper_evident_telemetry is None:
            return
        try:
            tamper_evident_telemetry.set_db(self.db)
            resolved_polyphonic = polyphonic_context if isinstance(polyphonic_context, dict) else {}
            voice_profile = (
                resolved_polyphonic.get("voice_profile")
                if isinstance(resolved_polyphonic.get("voice_profile"), dict)
                else {}
            )
            resolved_targets = [str(t) for t in (targets or []) if t]
            if not resolved_targets:
                resolved_targets = [str(x) for x in [queue_id, command_id, token_id] if x]
            tamper_evident_telemetry.record_action(
                principal=f"service:{actor or 'governance_executor'}",
                principal_trust_state="trusted",
                action=f"governance_execution:{action_type}",
                targets=resolved_targets,
                policy_decision_id=decision_id,
                governance_decision_id=decision_id,
                governance_queue_id=queue_id,
                token_id=token_id,
                execution_id=execution_id or command_id or "",
                trace_id=trace_id,
                constraints={
                    "command_type": command_type,
                    "reason": reason,
                    "voice_type": voice_profile.get("voice_type"),
                    "capability_class": voice_profile.get("capability_class"),
                },
                result="success" if outcome == "executed" else ("denied" if outcome == "skipped" else "failed"),
                result_details=reason,
            )
        except Exception:
            logger.exception(
                "Failed to record governance execution audit for decision=%s queue=%s",
                decision_id,
                queue_id,
            )

    async def _run_domain_operation(
        self,
        *,
        action_type: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        if action_type == "response_block_ip":
            from threat_response import ResponseStatus, firewall

            ip = str(payload.get("ip") or "").strip()
            if not ip:
                raise ValueError("Missing ip for response_block_ip")
            reason = str(payload.get("reason") or "Governed block")
            duration_hours = int(payload.get("duration_hours") or 24)
            result = await firewall.block_ip(ip=ip, reason=reason, duration_hours=duration_hours)
            if result.status != ResponseStatus.SUCCESS:
                raise RuntimeError(result.message)
            return {"operation": action_type, "ip": ip, "details": result.details}

        if action_type == "response_unblock_ip":
            from threat_response import ResponseStatus, firewall

            ip = str(payload.get("ip") or "").strip()
            if not ip:
                raise ValueError("Missing ip for response_unblock_ip")
            result = await firewall.unblock_ip(ip=ip)
            if result.status != ResponseStatus.SUCCESS:
                raise RuntimeError(result.message)
            return {"operation": action_type, "ip": ip, "details": result.details}

        if action_type == "quarantine_restore":
            from quarantine import restore_file

            entry_id = str(payload.get("entry_id") or "").strip()
            if not entry_id:
                raise ValueError("Missing entry_id for quarantine_restore")
            restored = bool(restore_file(entry_id))
            if not restored:
                raise RuntimeError(f"Failed to restore quarantined entry: {entry_id}")
            return {"operation": action_type, "entry_id": entry_id, "restored": True}

        if action_type == "quarantine_delete":
            from quarantine import delete_quarantined

            entry_id = str(payload.get("entry_id") or "").strip()
            if not entry_id:
                raise ValueError("Missing entry_id for quarantine_delete")
            deleted = bool(delete_quarantined(entry_id))
            if not deleted:
                raise RuntimeError(f"Failed to delete quarantined entry: {entry_id}")
            return {"operation": action_type, "entry_id": entry_id, "deleted": True}

        if action_type == "quarantine_agent":
            try:
                from services.identity import identity_service
            except Exception:
                from backend.services.identity import identity_service

            identity_service.set_db(self.db)
            agent_id = str(payload.get("agent_id") or "").strip()
            reason = str(payload.get("reason") or "Governed quarantine")
            if not agent_id:
                raise ValueError("Missing agent_id for quarantine_agent")
            quarantined = bool(identity_service.quarantine_agent(agent_id=agent_id, reason=reason))
            if not quarantined:
                raise RuntimeError(f"Failed to quarantine agent: {agent_id}")
            return {"operation": action_type, "agent_id": agent_id, "quarantined": True}

        if action_type in {
            "vpn_initialize",
            "vpn_start",
            "vpn_stop",
            "vpn_peer_add",
            "vpn_peer_remove",
            "vpn_kill_switch_enable",
            "vpn_kill_switch_disable",
        }:
            from vpn_integration import vpn_manager

            if action_type == "vpn_initialize":
                result = await vpn_manager.initialize()
            elif action_type == "vpn_start":
                result = await vpn_manager.start()
            elif action_type == "vpn_stop":
                result = await vpn_manager.stop()
            elif action_type == "vpn_peer_add":
                peer_name = str(payload.get("peer_name") or payload.get("name") or "").strip()
                if not peer_name:
                    raise ValueError("Missing peer_name for vpn_peer_add")
                result = await vpn_manager.add_peer(peer_name)
            elif action_type == "vpn_peer_remove":
                peer_id = str(payload.get("peer_id") or "").strip()
                if not peer_id:
                    raise ValueError("Missing peer_id for vpn_peer_remove")
                removed = bool(await vpn_manager.remove_peer(peer_id))
                if not removed:
                    raise RuntimeError(f"Failed to remove VPN peer: {peer_id}")
                result = {"peer_id": peer_id, "removed": True}
            elif action_type == "vpn_kill_switch_enable":
                result = await vpn_manager.kill_switch.enable()
            else:
                result = await vpn_manager.kill_switch.disable()
            return {"operation": action_type, "result": result}

        raise ValueError(f"Unsupported domain action_type: {action_type}")

    async def _execute_domain_operation(
        self,
        *,
        decision: Dict[str, Any],
        queue_doc: Dict[str, Any],
        payload: Dict[str, Any],
        actor: str,
        action_type: str,
    ) -> Dict[str, Any]:
        decision_id = decision.get("decision_id")
        related_queue_id = queue_doc.get("queue_id")
        polyphonic_context = queue_doc.get("polyphonic_context") or payload.get("polyphonic_context") or {}
        now = _iso_now()
        try:
            op_result = await self._run_domain_operation(action_type=action_type, payload=payload)
            await self.db.triune_outbound_queue.update_one(
                {"queue_id": related_queue_id},
                {
                    "$set": {
                        "status": "released_to_execution",
                        "released_at": now,
                        "updated_at": now,
                        "execution_result": op_result,
                        "polyphonic_context": polyphonic_context or None,
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
                        "polyphonic_context": polyphonic_context or None,
                        "voice_type": ((polyphonic_context.get("voice_profile") or {}).get("voice_type") if isinstance(polyphonic_context, dict) else None),
                        "capability_class": ((polyphonic_context.get("voice_profile") or {}).get("capability_class") if isinstance(polyphonic_context, dict) else None),
                    }
                },
            )
            if emit_world_event is not None:
                await emit_world_event(
                    self.db,
                    event_type="governance_domain_operation_executed",
                    entity_refs=[decision_id, related_queue_id, action_type],
                    payload={
                        **op_result,
                        "polyphonic_context": polyphonic_context or None,
                        "voice_type": ((polyphonic_context.get("voice_profile") or {}).get("voice_type") if isinstance(polyphonic_context, dict) else None),
                        "capability_class": ((polyphonic_context.get("voice_profile") or {}).get("capability_class") if isinstance(polyphonic_context, dict) else None),
                    },
                    trigger_triune=False,
                    source="governance_executor",
                )
            resolved_execution_id = str(
                op_result.get("execution_id")
                or op_result.get("entry_id")
                or op_result.get("ip")
                or op_result.get("agent_id")
                or f"{action_type}:{decision_id}"
            )
            resolved_token_id = str(payload.get("token_id") or "")
            resolved_trace_id = str(payload.get("trace_id") or "")
            self._record_execution_audit(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type=action_type,
                outcome="executed",
                actor=actor,
                command_type=action_type,
                token_id=resolved_token_id,
                execution_id=resolved_execution_id,
                trace_id=resolved_trace_id,
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
                targets=[
                    payload.get("agent_id"),
                    payload.get("entry_id"),
                    payload.get("ip"),
                    payload.get("peer_id"),
                    payload.get("peer_name"),
                    related_queue_id,
                ],
            )
            await self._emit_execution_completion_event(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type=action_type,
                outcome="executed",
                reason=action_type,
                command_type=action_type,
                token_id=resolved_token_id,
                execution_id=resolved_execution_id,
                trace_id=resolved_trace_id,
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
            )
            return {"outcome": "executed", "result": op_result}
        except Exception as exc:
            error_reason = str(exc)
            logger.exception(
                "Failed domain operation '%s' for decision %s: %s",
                action_type,
                decision_id,
                exc,
            )
            await self.db.triune_decisions.update_one(
                {"decision_id": decision_id},
                {
                    "$set": {
                        "execution_status": "failed",
                        "execution_error": error_reason,
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
            self._record_execution_audit(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type=action_type,
                outcome="failed",
                reason=error_reason,
                actor=actor,
                command_type=action_type,
                token_id=str(payload.get("token_id") or ""),
                execution_id=str(payload.get("entry_id") or payload.get("ip") or f"{action_type}:{decision_id}"),
                trace_id=str(payload.get("trace_id") or ""),
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
                targets=[
                    payload.get("agent_id"),
                    payload.get("entry_id"),
                    payload.get("ip"),
                    payload.get("peer_id"),
                    payload.get("peer_name"),
                    related_queue_id,
                ],
            )
            await self._emit_execution_completion_event(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type=action_type,
                outcome="failed",
                reason=error_reason,
                command_type=action_type,
                token_id=str(payload.get("token_id") or ""),
                execution_id=str(payload.get("entry_id") or payload.get("ip") or f"{action_type}:{decision_id}"),
                trace_id=str(payload.get("trace_id") or ""),
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
            )
            return {"outcome": "failed", "reason": "domain_operation_exception"}

    async def _execute_tool_runtime_operation(
        self,
        *,
        decision: Dict[str, Any],
        queue_doc: Dict[str, Any],
        payload: Dict[str, Any],
        actor: str,
    ) -> Dict[str, Any]:
        decision_id = decision.get("decision_id")
        related_queue_id = queue_doc.get("queue_id")
        polyphonic_context = queue_doc.get("polyphonic_context") or payload.get("polyphonic_context") or {}
        now = _iso_now()
        tool = str(payload.get("tool") or "").strip().lower()
        runtime_target = str(payload.get("runtime_target") or "server").strip().lower()
        agent_id = str(payload.get("agent_id") or "").strip() or None
        params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
        params = dict(params or {})
        # Backward compatibility for legacy payload shapes.
        if payload.get("domain") and not params.get("domain"):
            params["domain"] = payload.get("domain")
        if payload.get("collection_name") and not params.get("collection_name"):
            params["collection_name"] = payload.get("collection_name")
        if payload.get("target") and not params.get("target"):
            params["target"] = payload.get("target")
        if payload.get("options") and not params.get("options"):
            params["options"] = payload.get("options")

        governance_context = self._governance_context_for_execution(
            decision_id=decision_id,
            queue_id=related_queue_id,
            action_type="tool_execution",
        )
        try:
            from integrations_manager import run_runtime_tool

            job = await run_runtime_tool(
                tool=tool,
                params=params,
                runtime_target=runtime_target,
                agent_id=agent_id,
                actor=actor,
                governance_context=governance_context,
            )
            op_result = {
                "operation": "tool_execution",
                "tool": tool,
                "runtime_target": runtime_target,
                "agent_id": agent_id,
                "job_id": job.get("id"),
                "job_status": job.get("status"),
                "job_result": job.get("result"),
            }
            await self.db.triune_outbound_queue.update_one(
                {"queue_id": related_queue_id},
                {
                    "$set": {
                        "status": "released_to_execution",
                        "released_at": now,
                        "updated_at": now,
                        "execution_result": op_result,
                        "polyphonic_context": polyphonic_context or None,
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
                        "polyphonic_context": polyphonic_context or None,
                        "voice_type": ((polyphonic_context.get("voice_profile") or {}).get("voice_type") if isinstance(polyphonic_context, dict) else None),
                        "capability_class": ((polyphonic_context.get("voice_profile") or {}).get("capability_class") if isinstance(polyphonic_context, dict) else None),
                    }
                },
            )
            if emit_world_event is not None:
                await emit_world_event(
                    self.db,
                    event_type="governance_tool_execution_executed",
                    entity_refs=[decision_id, related_queue_id, tool, str(job.get("id"))],
                    payload={
                        **op_result,
                        "polyphonic_context": polyphonic_context or None,
                        "voice_type": ((polyphonic_context.get("voice_profile") or {}).get("voice_type") if isinstance(polyphonic_context, dict) else None),
                        "capability_class": ((polyphonic_context.get("voice_profile") or {}).get("capability_class") if isinstance(polyphonic_context, dict) else None),
                    },
                    trigger_triune=False,
                    source="governance_executor",
                )
            self._record_execution_audit(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type="tool_execution",
                outcome="executed",
                actor=actor,
                command_id=str(job.get("id") or ""),
                command_type=f"tool:{tool}",
                execution_id=str(job.get("id") or f"{tool}:{decision_id}"),
                trace_id=str(payload.get("trace_id") or ""),
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
                targets=[tool, runtime_target, agent_id, related_queue_id],
            )
            await self._emit_execution_completion_event(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type="tool_execution",
                outcome="executed",
                reason=f"tool:{tool}",
                command_id=str(job.get("id") or ""),
                command_type=f"tool:{tool}",
                execution_id=str(job.get("id") or f"{tool}:{decision_id}"),
                trace_id=str(payload.get("trace_id") or ""),
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
            )
            return {"outcome": "executed", "result": op_result}
        except Exception as exc:
            error_reason = str(exc)
            logger.exception("Failed tool execution for decision %s: %s", decision_id, exc)
            await self.db.triune_decisions.update_one(
                {"decision_id": decision_id},
                {
                    "$set": {
                        "execution_status": "failed",
                        "execution_error": error_reason,
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
            self._record_execution_audit(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type="tool_execution",
                outcome="failed",
                reason=error_reason,
                actor=actor,
                command_type=f"tool:{tool}",
                execution_id=str(payload.get("command_id") or f"{tool}:{decision_id}"),
                trace_id=str(payload.get("trace_id") or ""),
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
                targets=[tool, runtime_target, agent_id, related_queue_id],
            )
            await self._emit_execution_completion_event(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type="tool_execution",
                outcome="failed",
                reason=error_reason,
                command_type=f"tool:{tool}",
                execution_id=str(payload.get("command_id") or f"{tool}:{decision_id}"),
                trace_id=str(payload.get("trace_id") or ""),
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
            )
            return {"outcome": "failed", "reason": "tool_execution_exception"}

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
            reason = f"Queue document not found: {related_queue_id}"
            await self.db.triune_decisions.update_one(
                {"decision_id": decision_id},
                {
                    "$set": {
                        "execution_status": "failed",
                        "execution_error": reason,
                        "updated_at": now,
                    }
                },
            )
            self._record_execution_audit(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type="unknown",
                outcome="failed",
                reason=reason,
            )
            await self._emit_execution_completion_event(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type="unknown",
                outcome="failed",
                reason=reason,
            )
            return {"outcome": "failed", "reason": "queue_not_found"}

        action_type = str(queue_doc.get("action_type") or "").lower()
        payload = queue_doc.get("payload") or {}
        polyphonic_context = queue_doc.get("polyphonic_context") or payload.get("polyphonic_context") or {}
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

        if action_type in self.DOMAIN_OPERATION_ACTIONS:
            return await self._execute_domain_operation(
                decision=decision,
                queue_doc=queue_doc,
                payload=payload,
                actor=actor,
                action_type=action_type,
            )

        if action_type == "tool_execution":
            return await self._execute_tool_runtime_operation(
                decision=decision,
                queue_doc=queue_doc,
                payload=payload,
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
            self._record_execution_audit(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type=action_type,
                outcome="skipped",
                reason="unsupported_action_type",
                actor=actor,
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
                targets=[related_queue_id, decision_id, action_type],
            )
            await self._emit_execution_completion_event(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type=action_type,
                outcome="skipped",
                reason="unsupported_action_type",
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
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
            reason = "missing agent_id or command_id in approved payload"
            await self.db.triune_decisions.update_one(
                {"decision_id": decision_id},
                {
                    "$set": {
                        "execution_status": "failed",
                        "execution_error": reason,
                        "updated_at": now,
                    }
                },
            )
            self._record_execution_audit(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type=action_type,
                outcome="failed",
                reason=reason,
                actor=actor,
                command_id=command_id,
                command_type=command_type,
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
                targets=[agent_id, command_id, related_queue_id],
            )
            await self._emit_execution_completion_event(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type=action_type,
                outcome="failed",
                reason=reason,
                command_id=command_id,
                command_type=command_type,
                execution_id=command_id,
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
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
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
            )

            await self.db.agent_commands.update_many(
                {
                    "$or": [
                        {"decision_id": decision_id},
                        {"command_id": command_id},
                    ]
                },
                {
                    "$set": {
                        "status": "pending",
                        "updated_at": now,
                        "decision_context": {
                            "decision_id": decision_id,
                            "queue_id": related_queue_id,
                            "approved": True,
                            "released_to_execution": True,
                        },
                        "authority_context": {
                            "principal": actor,
                            "capability": command_type,
                            "target": str((parameters or {}).get("target") or agent_id),
                            "token_id": str(payload.get("token_id") or (parameters or {}).get("token_id") or ""),
                            "scope": {"zone_from": "governance", "zone_to": "agent_control_zone"},
                            "contract_version": "endpoint-boundary.v1",
                        },
                        "polyphonic_context": polyphonic_context or None,
                    },
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
                        "polyphonic_context": polyphonic_context or None,
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
                        "polyphonic_context": polyphonic_context or None,
                        "voice_type": ((polyphonic_context.get("voice_profile") or {}).get("voice_type") if isinstance(polyphonic_context, dict) else None),
                        "capability_class": ((polyphonic_context.get("voice_profile") or {}).get("capability_class") if isinstance(polyphonic_context, dict) else None),
                    }
                },
            )
            if emit_world_event is not None:
                await emit_world_event(
                    self.db,
                    event_type="governance_decision_executed",
                    entity_refs=[decision_id, related_queue_id, agent_id, command_id],
                    payload={
                        "action_type": action_type,
                        "command_type": command_type,
                        "polyphonic_context": polyphonic_context or None,
                        "voice_type": ((polyphonic_context.get("voice_profile") or {}).get("voice_type") if isinstance(polyphonic_context, dict) else None),
                        "capability_class": ((polyphonic_context.get("voice_profile") or {}).get("capability_class") if isinstance(polyphonic_context, dict) else None),
                    },
                    trigger_triune=False,
                    source="governance_executor",
                )
            self._record_execution_audit(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type=action_type,
                outcome="executed",
                actor=actor,
                command_id=command_id,
                command_type=command_type,
                token_id=str(payload.get("token_id") or ""),
                execution_id=command_id,
                trace_id=str(payload.get("trace_id") or ""),
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
                targets=[agent_id, command_id, related_queue_id],
            )
            await self._emit_execution_completion_event(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type=action_type,
                outcome="executed",
                command_id=command_id,
                command_type=command_type,
                token_id=str(payload.get("token_id") or ""),
                execution_id=command_id,
                trace_id=str(payload.get("trace_id") or ""),
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
            )
            return {"outcome": "executed"}
        except Exception as exc:
            logger.exception("Failed to execute approved decision %s: %s", decision_id, exc)
            error_reason = str(exc)
            await self.db.triune_decisions.update_one(
                {"decision_id": decision_id},
                {
                    "$set": {
                        "execution_status": "failed",
                        "execution_error": error_reason,
                        "updated_at": _iso_now(),
                    }
                },
            )
            self._record_execution_audit(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type=action_type,
                outcome="failed",
                reason=error_reason,
                actor=actor,
                command_id=command_id,
                command_type=command_type,
                token_id=str(payload.get("token_id") or ""),
                execution_id=command_id,
                trace_id=str(payload.get("trace_id") or ""),
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
                targets=[agent_id, command_id, related_queue_id],
            )
            await self._emit_execution_completion_event(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type=action_type,
                outcome="failed",
                reason=error_reason,
                command_id=command_id,
                command_type=command_type,
                token_id=str(payload.get("token_id") or ""),
                execution_id=command_id,
                trace_id=str(payload.get("trace_id") or ""),
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
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
        polyphonic_context = queue_doc.get("polyphonic_context") or payload.get("polyphonic_context") or {}
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
                        "polyphonic_context": polyphonic_context or None,
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
                        "polyphonic_context": polyphonic_context or None,
                        "voice_type": ((polyphonic_context.get("voice_profile") or {}).get("voice_type") if isinstance(polyphonic_context, dict) else None),
                        "capability_class": ((polyphonic_context.get("voice_profile") or {}).get("capability_class") if isinstance(polyphonic_context, dict) else None),
                    }
                },
            )
            if emit_world_event is not None:
                await emit_world_event(
                    self.db,
                    event_type="governance_token_operation_executed",
                    entity_refs=[decision_id, related_queue_id, operation],
                    payload={
                        **op_result,
                        "polyphonic_context": polyphonic_context or None,
                        "voice_type": ((polyphonic_context.get("voice_profile") or {}).get("voice_type") if isinstance(polyphonic_context, dict) else None),
                        "capability_class": ((polyphonic_context.get("voice_profile") or {}).get("capability_class") if isinstance(polyphonic_context, dict) else None),
                    },
                    trigger_triune=False,
                    source="governance_executor",
                )
            resolved_token_id = str(op_result.get("token_id") or "")
            resolved_trace_id = str(payload.get("trace_id") or "")
            self._record_execution_audit(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type=action_type,
                outcome="executed",
                actor=actor,
                token_id=resolved_token_id,
                execution_id=resolved_token_id or f"{operation}:{decision_id}",
                trace_id=resolved_trace_id,
                command_type=operation,
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
                targets=[payload.get("principal"), resolved_token_id, related_queue_id],
            )
            await self._emit_execution_completion_event(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type=action_type,
                outcome="executed",
                reason=operation,
                command_type=operation,
                token_id=resolved_token_id,
                execution_id=resolved_token_id or f"{operation}:{decision_id}",
                trace_id=resolved_trace_id,
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
            )
            return {"outcome": "executed", "result": op_result}
        except Exception as exc:
            logger.exception("Failed token operation '%s' for decision %s: %s", operation, decision_id, exc)
            error_reason = str(exc)
            await self.db.triune_decisions.update_one(
                {"decision_id": decision_id},
                {
                    "$set": {
                        "execution_status": "failed",
                        "execution_error": error_reason,
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
            self._record_execution_audit(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type=action_type,
                outcome="failed",
                reason=error_reason,
                actor=actor,
                command_type=operation,
                token_id=str(payload.get("token_id") or ""),
                execution_id=str(payload.get("token_id") or f"{operation}:{decision_id}"),
                trace_id=str(payload.get("trace_id") or ""),
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
                targets=[payload.get("principal"), payload.get("token_id"), related_queue_id],
            )
            await self._emit_execution_completion_event(
                decision_id=decision_id,
                queue_id=related_queue_id,
                action_type=action_type,
                outcome="failed",
                reason=error_reason,
                command_type=operation,
                token_id=str(payload.get("token_id") or ""),
                execution_id=str(payload.get("token_id") or f"{operation}:{decision_id}"),
                trace_id=str(payload.get("trace_id") or ""),
                polyphonic_context=polyphonic_context if isinstance(polyphonic_context, dict) else None,
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
