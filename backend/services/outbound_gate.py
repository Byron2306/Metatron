from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import secrets
import logging

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
        self.epoch_service = get_governance_epoch_service(db)
        self.notation_tokens = get_notation_token_service(db)

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
        polyphonic_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Queue action for approval. Mandatory for high-impact action types."""
        normalized_action = str(action_type or "unknown").strip().lower()
        normalized_impact = self._normalize_impact(impact_level)
        resolved_polyphonic_context = polyphonic_context or payload.get("polyphonic_context") or {}
        voice_profile = (
            resolved_polyphonic_context.get("voice_profile")
            if isinstance(resolved_polyphonic_context, dict)
            else {}
        )

        # Governance hardening: these paths cannot skip triune and cannot be low impact.
        if normalized_action in MANDATORY_HIGH_IMPACT_ACTIONS:
            requires_triune = True
            if IMPACT_ORDER[normalized_impact] < IMPACT_ORDER["high"]:
                normalized_impact = "high"

        scope = str(
            (payload.get("target_domain") or (payload.get("parameters") or {}).get("target_domain") or "global")
        )
        active_epoch = await self.epoch_service.get_active_epoch(scope=scope)
        active_epoch_doc = (
            active_epoch.model_dump() if (active_epoch is not None and hasattr(active_epoch, "model_dump")) else (
                active_epoch.dict() if active_epoch is not None else {}
            )
        )
        notation_token = None
        notation_token_id = None
        if isinstance(resolved_polyphonic_context, dict):
            notation_token = resolved_polyphonic_context.get("notation_token")
            notation_token_id = resolved_polyphonic_context.get("notation_token_id")
            if active_epoch is not None:
                resolved_polyphonic_context.setdefault("governance_epoch", active_epoch.epoch_id)
                resolved_polyphonic_context.setdefault("score_id", active_epoch.score_id)
                resolved_polyphonic_context.setdefault("genre_mode", active_epoch.genre_mode)
                resolved_polyphonic_context.setdefault("strictness_level", active_epoch.strictness_level)
                resolved_polyphonic_context.setdefault("world_state_hash", active_epoch.world_state_hash)
        notation_token = notation_token or payload.get("notation_token")
        notation_token_id = notation_token_id or payload.get("notation_token_id")
        if (not notation_token and not notation_token_id) and active_epoch is not None:
            try:
                issued = await self.notation_tokens.mint_notation_token(
                    epoch_id=active_epoch.epoch_id,
                    score_id=active_epoch.score_id,
                    genre_mode=active_epoch.genre_mode,
                    voice_role=str((voice_profile or {}).get("voice_type") or "governance_voice"),
                    capability_class=str((voice_profile or {}).get("capability_class") or "governance"),
                    world_state_hash=active_epoch.world_state_hash,
                    issued_to=str(subject_id or actor or "unknown"),
                    entry_window_ms=payload.get("entry_window_ms") or [0, 300000],
                    sequence_slot=payload.get("sequence_slot"),
                    required_companions=payload.get("required_companions") or [],
                    response_class=normalized_action,
                    ttl_seconds=int(payload.get("notation_ttl_seconds") or 600),
                )
                notation_token = issued.model_dump() if hasattr(issued, "model_dump") else issued.dict()
                notation_token_id = notation_token.get("token_id")
                if isinstance(resolved_polyphonic_context, dict):
                    resolved_polyphonic_context["notation_token"] = notation_token
                    resolved_polyphonic_context["notation_token_id"] = notation_token_id
                    resolved_polyphonic_context["notation_auto_issued"] = True
            except Exception:
                logger.debug("Failed auto-issuing notation token in gate_action", exc_info=True)
        validation_context = {
            "baseline_time": payload.get("created_at") or payload.get("requested_at"),
            "observed_slot": payload.get("sequence_slot"),
            "observed_companions": payload.get("observed_companions") or [],
            "enforce_sequence_slot": False,
            "enforce_required_companions": False,
        }
        notation_validation = await self.notation_tokens.validate_notation_token(
            token=notation_token or notation_token_id,
            active_epoch=active_epoch_doc if active_epoch_doc else None,
            world_state_hash=(
                active_epoch.world_state_hash
                if active_epoch is not None
                else (resolved_polyphonic_context.get("world_state_hash") if isinstance(resolved_polyphonic_context, dict) else None)
            ),
            context=validation_context,
        )
        notation_checks = notation_validation.get("checks") or {}
        notation_valid = bool(notation_validation.get("valid"))
        notation_failure_reason = ";".join(notation_validation.get("reasons") or []) or None
        world_state_hash_match = bool(notation_checks.get("world_state_hash_match", False))
        epoch_match = bool(notation_checks.get("epoch_match", False))
        score_match = bool(notation_checks.get("score_match", False))
        if isinstance(resolved_polyphonic_context, dict):
            if notation_validation.get("token"):
                resolved_polyphonic_context["notation_token"] = notation_validation.get("token")
                resolved_polyphonic_context["notation_token_id"] = (
                    (notation_validation.get("token") or {}).get("token_id")
                )
                notation_token_id = (notation_validation.get("token") or {}).get("token_id")
            if active_epoch is not None:
                resolved_polyphonic_context["governance_epoch_descriptor"] = active_epoch_doc

        now = datetime.now(timezone.utc).isoformat()
        queue_id = secrets.token_hex(8)
        decision_id = secrets.token_hex(8)
        action_id = payload.get("command_id") or payload.get("action_id") or secrets.token_hex(8)

        refs = [r for r in (entity_refs or []) if r]
        if subject_id and subject_id not in refs:
            refs.insert(0, subject_id)
        if isinstance(voice_profile, dict):
            if voice_profile.get("component_id"):
                refs.append(str(voice_profile.get("component_id")))
            if voice_profile.get("voice_type"):
                refs.append(str(voice_profile.get("voice_type")))

        payload_with_polyphonic = dict(payload or {})
        if resolved_polyphonic_context:
            payload_with_polyphonic["polyphonic_context"] = resolved_polyphonic_context
        if notation_token_id:
            payload_with_polyphonic["notation_token_id"] = notation_token_id
        if active_epoch is not None:
            payload_with_polyphonic.setdefault("governance_epoch", active_epoch.epoch_id)
            payload_with_polyphonic.setdefault("score_id", active_epoch.score_id)
            payload_with_polyphonic.setdefault("genre_mode", active_epoch.genre_mode)
            payload_with_polyphonic.setdefault("strictness_level", active_epoch.strictness_level)
            payload_with_polyphonic.setdefault("world_state_hash", active_epoch.world_state_hash)

        deny_for_notation = (
            (not notation_valid)
            and normalized_action in MANDATORY_HIGH_IMPACT_ACTIONS
        )
        queue_status = "denied" if deny_for_notation else "pending"
        decision_status = "denied" if deny_for_notation else "pending"
        execution_status = "skipped" if deny_for_notation else "awaiting_decision"

        queue_doc = {
            "queue_id": queue_id,
            "action_id": action_id,
            "action_type": normalized_action,
            "subject_id": subject_id,
            "actor": actor,
            "impact_level": normalized_impact,
            "payload": payload_with_polyphonic,
            "voice_type": voice_profile.get("voice_type") if isinstance(voice_profile, dict) else None,
            "capability_class": voice_profile.get("capability_class") if isinstance(voice_profile, dict) else None,
            "polyphonic_context": resolved_polyphonic_context or None,
            "governance_epoch": active_epoch.epoch_id if active_epoch is not None else None,
            "score_id": active_epoch.score_id if active_epoch is not None else None,
            "genre_mode": active_epoch.genre_mode if active_epoch is not None else None,
            "strictness_level": active_epoch.strictness_level if active_epoch is not None else None,
            "world_state_hash": active_epoch.world_state_hash if active_epoch is not None else None,
            "notation_token_id": notation_token_id,
            "notation_valid": notation_valid,
            "notation_failure_reason": notation_failure_reason,
            "world_state_hash_match": world_state_hash_match,
            "epoch_match": epoch_match,
            "score_match": score_match,
            "status": queue_status,
            "execution_status": execution_status,
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
            "source": "outbound_gate",
            "status": "pending",
            "execution_status": execution_status,
            "voice_type": voice_profile.get("voice_type") if isinstance(voice_profile, dict) else None,
            "capability_class": voice_profile.get("capability_class") if isinstance(voice_profile, dict) else None,
            "polyphonic_context": resolved_polyphonic_context or None,
            "governance_epoch": active_epoch.epoch_id if active_epoch is not None else None,
            "score_id": active_epoch.score_id if active_epoch is not None else None,
            "genre_mode": active_epoch.genre_mode if active_epoch is not None else None,
            "strictness_level": active_epoch.strictness_level if active_epoch is not None else None,
            "world_state_hash": active_epoch.world_state_hash if active_epoch is not None else None,
            "notation_token_id": notation_token_id,
            "notation_valid": notation_valid,
            "notation_failure_reason": notation_failure_reason,
            "world_state_hash_match": world_state_hash_match,
            "epoch_match": epoch_match,
            "score_match": score_match,
            "status": decision_status,
            "created_at": now,
            "updated_at": now,
            "notes": (
                f"Notation denied before triune approval: {normalized_action} | {notation_failure_reason}"
                if deny_for_notation
                else f"Queued for triune approval: {normalized_action}"
            ),
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
                        "status": queue_status,
                        "action_type": normalized_action,
                        "impact_level": normalized_impact,
                        "actor": actor,
                        "voice_type": voice_profile.get("voice_type") if isinstance(voice_profile, dict) else None,
                        "capability_class": voice_profile.get("capability_class") if isinstance(voice_profile, dict) else None,
                        "polyphonic_context": resolved_polyphonic_context or None,
                        "governance_epoch": active_epoch.epoch_id if active_epoch is not None else None,
                        "score_id": active_epoch.score_id if active_epoch is not None else None,
                        "genre_mode": active_epoch.genre_mode if active_epoch is not None else None,
                        "world_state_hash": active_epoch.world_state_hash if active_epoch is not None else None,
                        "notation_token_id": notation_token_id,
                        "notation_valid": notation_valid,
                        "notation_failure_reason": notation_failure_reason,
                        "world_state_hash_match": world_state_hash_match,
                        "epoch_match": epoch_match,
                        "score_match": score_match,
                    },
                    trigger_triune=requires_triune,
                    source="outbound_gate",
                )
            except Exception:
                logger.debug("World event emit failed for queued outbound action", exc_info=True)

        return {
            "status": "denied" if deny_for_notation else "queued",
            "action_id": action_id,
            "queue_id": queue_id,
            "decision_id": decision_id,
            "action_type": normalized_action,
            "impact_level": normalized_impact,
            "voice_type": voice_profile.get("voice_type") if isinstance(voice_profile, dict) else None,
            "capability_class": voice_profile.get("capability_class") if isinstance(voice_profile, dict) else None,
            "polyphonic_context": resolved_polyphonic_context or None,
            "governance_epoch": active_epoch.epoch_id if active_epoch is not None else None,
            "score_id": active_epoch.score_id if active_epoch is not None else None,
            "genre_mode": active_epoch.genre_mode if active_epoch is not None else None,
            "world_state_hash": active_epoch.world_state_hash if active_epoch is not None else None,
            "notation_token_id": notation_token_id,
            "notation_valid": notation_valid,
            "notation_failure_reason": notation_failure_reason,
            "world_state_hash_match": world_state_hash_match,
            "epoch_match": epoch_match,
            "score_match": score_match,
            "message": (
                "Action denied due to notation validation failure"
                if deny_for_notation
                else "Action queued for triune approval"
            ),
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
