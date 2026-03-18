from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    from services.governance_epoch import get_governance_epoch_service
except Exception:
    from backend.services.governance_epoch import get_governance_epoch_service

try:
    from services.notation_token import get_notation_token_service
except Exception:
    from backend.services.notation_token import get_notation_token_service

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
        self.epoch_service = get_governance_epoch_service(db)
        self.notation_tokens = get_notation_token_service(db)

    async def _validate_notation_for_approval(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        related_queue_id = decision.get("related_queue_id")
        if not related_queue_id:
            return {"valid": True, "checks": {}, "reasons": [], "queue_doc": None}
        queue_doc = await self.db.triune_outbound_queue.find_one({"queue_id": related_queue_id}, {"_id": 0})
        if not queue_doc:
            return {"valid": False, "checks": {"queue_present": False}, "reasons": ["related_queue_missing"], "queue_doc": None}
        payload = queue_doc.get("payload") or {}
        polyphonic = queue_doc.get("polyphonic_context") or payload.get("polyphonic_context") or {}
        token = (
            (polyphonic.get("notation_token") if isinstance(polyphonic, dict) else None)
            or (polyphonic.get("notation_token_id") if isinstance(polyphonic, dict) else None)
            or queue_doc.get("notation_token_id")
            or payload.get("notation_token_id")
        )
        scope = str(payload.get("target_domain") or (payload.get("parameters") or {}).get("target_domain") or "global")
        active_epoch = await self.epoch_service.get_active_epoch(scope=scope)
        active_epoch_doc = (
            active_epoch.model_dump() if hasattr(active_epoch, "model_dump") else active_epoch.dict()
        ) if active_epoch is not None else None
        validation = await self.notation_tokens.validate_notation_token(
            token=token,
            active_epoch=active_epoch_doc,
            world_state_hash=active_epoch.world_state_hash if active_epoch is not None else None,
            context={
                "baseline_time": queue_doc.get("created_at"),
                "observed_slot": payload.get("sequence_slot"),
                "observed_companions": payload.get("observed_companions") or [],
                "enforce_sequence_slot": False,
                "enforce_required_companions": False,
            },
        )
        validation["queue_doc"] = queue_doc
        return validation

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
        notation_validation = await self._validate_notation_for_approval(decision)
        notation_valid = bool(notation_validation.get("valid"))
        notation_checks = notation_validation.get("checks") or {}
        notation_reason = ";".join(notation_validation.get("reasons") or []) or None
        if related_queue_id and not notation_valid:
            queue_doc = notation_validation.get("queue_doc") or {}
            polyphonic_ctx = queue_doc.get("polyphonic_context") or (queue_doc.get("payload") or {}).get("polyphonic_context") or {}
            notation_token_id = (
                (polyphonic_ctx.get("notation_token_id") if isinstance(polyphonic_ctx, dict) else None)
                or queue_doc.get("notation_token_id")
                or (queue_doc.get("payload") or {}).get("notation_token_id")
            )
            await self.db.triune_decisions.update_one(
                {"decision_id": decision_id},
                {
                    "$set": {
                        "status": "denied",
                        "denied_by": actor,
                        "denied_at": now,
                        "updated_at": now,
                        "execution_status": "skipped",
                        "denial_reason": notation_reason or "notation_validation_failed",
                        "notation_valid": False,
                        "notation_failure_reason": notation_reason,
                        "world_state_hash_match": bool(notation_checks.get("world_state_hash_match", False)),
                        "epoch_match": bool(notation_checks.get("epoch_match", False)),
                        "score_match": bool(notation_checks.get("score_match", False)),
                    }
                },
            )
            await self.db.triune_outbound_queue.update_one(
                {"queue_id": related_queue_id},
                {
                    "$set": {
                        "status": "denied",
                        "denied_by": actor,
                        "denied_at": now,
                        "updated_at": now,
                        "execution_status": "skipped",
                        "notation_valid": False,
                        "notation_failure_reason": notation_reason,
                        "world_state_hash_match": bool(notation_checks.get("world_state_hash_match", False)),
                        "epoch_match": bool(notation_checks.get("epoch_match", False)),
                        "score_match": bool(notation_checks.get("score_match", False)),
                    }
                },
            )
            if notation_token_id:
                await self.notation_tokens.revoke_notation_token(
                    str(notation_token_id),
                    reason=notation_reason or "approval_notation_validation_failed",
                )
            if emit_world_event is not None:
                try:
                    await emit_world_event(
                        self.db,
                        event_type="governance_decision_denied",
                        entity_refs=[decision_id, related_queue_id],
                        payload={
                            "actor": actor,
                            "reason": notation_reason or "notation_validation_failed",
                            "source": source,
                            "notation_valid": False,
                            "notation_failure_reason": notation_reason,
                            "world_state_hash_match": bool(notation_checks.get("world_state_hash_match", False)),
                            "epoch_match": bool(notation_checks.get("epoch_match", False)),
                            "score_match": bool(notation_checks.get("score_match", False)),
                        },
                        trigger_triune=False,
                        source=source,
                    )
                except Exception:
                    pass
            return {
                "found": True,
                "decision_id": decision_id,
                "related_queue_id": related_queue_id,
                "execution_status": "skipped",
                "denied": True,
                "notation_valid": False,
                "notation_failure_reason": notation_reason,
            }
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
                    "notation_valid": notation_valid,
                    "notation_failure_reason": notation_reason,
                    "world_state_hash_match": bool(notation_checks.get("world_state_hash_match", True)),
                    "epoch_match": bool(notation_checks.get("epoch_match", True)),
                    "score_match": bool(notation_checks.get("score_match", True)),
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
                        "notation_valid": notation_valid,
                        "notation_failure_reason": notation_reason,
                        "world_state_hash_match": bool(notation_checks.get("world_state_hash_match", True)),
                        "epoch_match": bool(notation_checks.get("epoch_match", True)),
                        "score_match": bool(notation_checks.get("score_match", True)),
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
            try:
                await emit_world_event(
                    self.db,
                    event_type="governance_decision_approved",
                    entity_refs=[decision_id, related_queue_id],
                    payload={
                        "actor": actor,
                        "notes": notes,
                        "source": source,
                        "notation_valid": notation_valid,
                        "notation_failure_reason": notation_reason,
                        "world_state_hash_match": bool(notation_checks.get("world_state_hash_match", True)),
                        "epoch_match": bool(notation_checks.get("epoch_match", True)),
                        "score_match": bool(notation_checks.get("score_match", True)),
                    },
                    trigger_triune=False,
                    source=source,
                )
            except Exception:
                pass

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
        queue_doc = None
        if related_queue_id:
            queue_doc = await self.db.triune_outbound_queue.find_one({"queue_id": related_queue_id}, {"_id": 0})
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
            if queue_doc:
                polyphonic_ctx = queue_doc.get("polyphonic_context") or (queue_doc.get("payload") or {}).get("polyphonic_context") or {}
                notation_token_id = (
                    (polyphonic_ctx.get("notation_token_id") if isinstance(polyphonic_ctx, dict) else None)
                    or queue_doc.get("notation_token_id")
                    or (queue_doc.get("payload") or {}).get("notation_token_id")
                )
                if notation_token_id:
                    await self.notation_tokens.revoke_notation_token(
                        str(notation_token_id),
                        reason=reason or "decision_denied",
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
            try:
                await emit_world_event(
                    self.db,
                    event_type="governance_decision_denied",
                    entity_refs=[decision_id, related_queue_id],
                    payload={"actor": actor, "reason": reason, "source": source},
                    trigger_triune=False,
                    source=source,
                )
            except Exception:
                pass

        return {
            "found": True,
            "decision_id": decision_id,
            "related_queue_id": related_queue_id,
            "execution_status": "skipped",
        }
