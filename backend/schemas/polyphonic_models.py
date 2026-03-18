from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from pydantic import BaseModel, Field
except Exception:
    class BaseModel:  # type: ignore
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)

        def dict(self) -> Dict[str, Any]:
            return dict(self.__dict__)

        def model_dump(self) -> Dict[str, Any]:
            return self.dict()

    def Field(default=None, default_factory=None):  # type: ignore
        if default_factory is not None:
            return default_factory()
        return default


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class VoiceProfile(BaseModel):
    component_id: str
    component_type: str
    voice_type: str
    capability_class: str
    allowed_register: str
    timbre_profile: str
    allowed_score_roles: List[str] = Field(default_factory=list)
    trust_domain: Optional[str] = None
    notes: Optional[str] = None


class ActionIntent(BaseModel):
    tool_name: Optional[str] = None
    operation: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    resource_uris: List[str] = Field(default_factory=list)
    target_domain: Optional[str] = None


class ActionContextRefs(BaseModel):
    session_id: Optional[str] = None
    world_state_ref: Optional[str] = None
    decision_id: Optional[str] = None
    request_id: Optional[str] = None
    trace_id: Optional[str] = None


class PolyphonicContext(BaseModel):
    voice_profile: Optional[VoiceProfile] = None
    score_id: Optional[str] = None
    genre_mode: Optional[str] = None
    governance_epoch: Optional[str] = None
    strictness_level: Optional[str] = None
    world_state_hash: Optional[str] = None
    notation_token_id: Optional[str] = None
    notation_token: Optional[Dict[str, Any]] = None
    timing_features: Optional[Dict[str, Any]] = None
    harmonic_state: Optional[Dict[str, Any]] = None
    chorus_state: Optional[Dict[str, Any]] = None


class GovernanceEpoch(BaseModel):
    epoch_id: str
    score_id: str
    genre_mode: str
    strictness_level: str
    world_state_hash: str
    started_at: datetime
    expires_at: datetime
    reason: Optional[str] = None
    status: str = "active"
    scope: Optional[str] = None
    signature_ref: Optional[str] = None


class NotationToken(BaseModel):
    token_id: str
    epoch_id: str
    score_id: str
    genre_mode: str
    voice_role: str
    capability_class: str
    entry_window_ms: Optional[List[int]] = None
    sequence_slot: Optional[int] = None
    required_companions: List[str] = Field(default_factory=list)
    response_class: Optional[str] = None
    world_state_hash: str
    issued_to: str
    issued_at: datetime
    expires_at: datetime
    status: str = "issued"
    signature_ref: Optional[str] = None


class ActionRequestEnvelope(BaseModel):
    actor_id: str
    actor_type: str
    intent: ActionIntent
    context_refs: ActionContextRefs = Field(default_factory=ActionContextRefs)
    policy_refs: List[str] = Field(default_factory=list)
    evidence_hashes: List[str] = Field(default_factory=list)
    polyphonic_context: Optional[PolyphonicContext] = None
    created_at: datetime = Field(default_factory=utc_now)
