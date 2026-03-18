from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from services.outbound_gate import OutboundGateService
except Exception:
    from backend.services.outbound_gate import OutboundGateService

try:
    from services.polyphonic_governance import get_polyphonic_governance_service
except Exception:
    from backend.services.polyphonic_governance import get_polyphonic_governance_service

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
        self.polyphonic = get_polyphonic_governance_service()

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
        route: Optional[str] = None,
        component_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Gate and persist a command in agent_commands with uniform metadata."""
        envelope = self.polyphonic.build_action_request_envelope(
            actor_id=str(actor or "unknown"),
            actor_type="service_or_user",
            operation=str(action_type or "agent_command"),
            parameters=(command_doc.get("parameters") or command_doc.get("params") or {}),
            tool_name=command_doc.get("command_type") or command_doc.get("tool"),
            resource_uris=[agent_id] if agent_id else [],
            context_refs={
                "session_id": command_doc.get("session_id"),
                "decision_id": command_doc.get("decision_id"),
                "request_id": command_doc.get("command_id") or command_doc.get("action_id"),
                "trace_id": command_doc.get("trace_id"),
            },
            policy_refs=[str(x) for x in (command_doc.get("policy_refs") or []) if x],
            evidence_hashes=[str(x) for x in (command_doc.get("evidence_hashes") or []) if x],
            target_domain=command_doc.get("target_domain"),
        )
        envelope = self.polyphonic.attach_voice_profile(
            envelope,
            component_id=component_id or "governed_dispatch",
            route=route or "queue_gated_agent_command",
            tool_name=command_doc.get("command_type") or command_doc.get("tool"),
            component_type="orchestration",
        )
        polyphonic_context = self.polyphonic.serialize_polyphonic_context(envelope)
        queued = await self.gate.gate_action(
            action_type=action_type,
            actor=actor,
            payload=command_doc,
            impact_level=impact_level,
            subject_id=agent_id,
            entity_refs=entity_refs or [agent_id, command_doc.get("command_id")],
            requires_triune=requires_triune,
            polyphonic_context=polyphonic_context,
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
        if polyphonic_context:
            persisted["polyphonic_context"] = polyphonic_context

        await self.db.agent_commands.insert_one(persisted)

        if event_type and emit_world_event is not None:
            outbound_event_payload = dict(event_payload or {})
            if polyphonic_context and "polyphonic_context" not in outbound_event_payload:
                outbound_event_payload["polyphonic_context"] = polyphonic_context
                outbound_event_payload["voice_type"] = (
                    (polyphonic_context.get("voice_profile") or {}).get("voice_type")
                    if isinstance(polyphonic_context, dict)
                    else None
                )
                outbound_event_payload["capability_class"] = (
                    (polyphonic_context.get("voice_profile") or {}).get("capability_class")
                    if isinstance(polyphonic_context, dict)
                    else None
                )
            await emit_world_event(
                self.db,
                event_type=event_type,
                entity_refs=event_entity_refs or [agent_id, persisted.get("command_id")],
                payload=outbound_event_payload,
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
        polyphonic_context: Optional[Dict[str, Any]] = None,
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
        if polyphonic_context:
            queue_doc["polyphonic_context"] = polyphonic_context

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
                    "polyphonic_context": polyphonic_context or None,
                    "voice_type": ((polyphonic_context.get("voice_profile") or {}).get("voice_type") if isinstance(polyphonic_context, dict) else None),
                    "capability_class": ((polyphonic_context.get("voice_profile") or {}).get("capability_class") if isinstance(polyphonic_context, dict) else None),
                },
                trigger_triune=False,
                source="governed_dispatch",
            )

        return queue_doc
