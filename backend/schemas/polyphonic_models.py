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
    baseline_ref: Optional["BaselineRef"] = None
    timing_features: Optional["TimingFeatures"] = None
    harmonic_state: Optional["HarmonicState"] = None
    harmonic_history: Optional[List[Dict[str, Any]]] = None
    harmonic_timeline: Optional[Dict[str, Any]] = None
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


class TimingFeatures(BaseModel):
    sample_size: int
    timestamps_ms: Optional[List[float]] = None
    intervals_ms: List[float] = Field(default_factory=list)
    last_interval_ms: Optional[float] = None
    median_interval_ms: Optional[float] = None
    mean_interval_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    jitter_norm: Optional[float] = None
    drift_norm: Optional[float] = None
    burstiness: Optional[float] = None
    entropy_signature: Optional[float] = None
    sequence_class: Optional[str] = None
    dominant_frequency: Optional[float] = None


class BaselineRef(BaseModel):
    baseline_id: str
    scope_type: str
    actor_id: Optional[str] = None
    tool_name: Optional[str] = None
    target_domain: Optional[str] = None
    environment: Optional[str] = None
    version: str = "v1"
    source: str = "harmonic_engine"
    baseline_band: Optional[Dict[str, Any]] = None


class HarmonicState(BaseModel):
    resonance_score: float
    discord_score: float
    confidence: float
    baseline_ref: Optional[BaselineRef] = None
    mode_recommendation: Optional[str] = None
    drift_norm: Optional[float] = None
    jitter_norm: Optional[float] = None
    burstiness: Optional[float] = None
    entropy_signature: Optional[float] = None
    rationale: List[str] = Field(default_factory=list)


class ActionRequestEnvelope(BaseModel):
    actor_id: str
    actor_type: str
    intent: ActionIntent
    context_refs: ActionContextRefs = Field(default_factory=ActionContextRefs)
    policy_refs: List[str] = Field(default_factory=list)
    evidence_hashes: List[str] = Field(default_factory=list)
    polyphonic_context: Optional[PolyphonicContext] = None
    created_at: datetime = Field(default_factory=utc_now)
