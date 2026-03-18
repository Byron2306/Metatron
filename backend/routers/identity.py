"""
Identity Protection API Router (frontend compatibility)
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from collections import defaultdict
import ipaddress

from fastapi import APIRouter, Query, Depends
from pydantic import BaseModel

from identity_protection import get_identity_protection_engine

from .dependencies import get_db
try:
    from .dependencies import get_current_user, check_permission, require_machine_token
except Exception:
    def get_current_user(*args, **kwargs):
        return {"id": "system", "email": "system@local", "role": "admin"}

    def check_permission(required_permission: str):
        async def _checker(*a, **k):
            return {"id": "system", "email": "system@local", "role": "admin"}
        return _checker

    def require_machine_token(*args, **kwargs):
        async def _checker(*a, **k):
            return {"auth": "ok", "subject": "identity ingest"}
        return _checker
try:
    from services.world_events import emit_world_event
except Exception:
    from backend.services.world_events import emit_world_event
try:
    from services.outbound_gate import OutboundGateService
except Exception:
    from backend.services.outbound_gate import OutboundGateService
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

IDENTITY_INCIDENT_COLLECTION = "identity_incidents"
IDENTITY_EVENT_COLLECTION = "identity_provider_events"
IDENTITY_RESPONSE_ACTION_COLLECTION = "identity_response_actions"
IDENTITY_INCIDENT_TERMINAL_STATUSES = {"resolved", "suppressed", "false_positive"}
_identity_event_cache: List[Dict[str, Any]] = []
_IDENTITY_EVENT_CACHE_LIMIT = 5000
_identity_response_action_cache: List[Dict[str, Any]] = []
_IDENTITY_RESPONSE_ACTION_CACHE_LIMIT = 1000

def _incident_transition_entry(from_status: Optional[str], to_status: str, actor: str, reason: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "from_status": from_status,
        "to_status": to_status,
        "actor": actor,
        "reason": reason,
    }
    if metadata:
        entry["metadata"] = metadata
    return entry

def _incident_doc_from_threat(threat: Dict[str, Any]) -> Dict[str, Any]:
    status = str(threat.get("status") or "active")
    now = datetime.now(timezone.utc).isoformat()
    doc = dict(threat)
    doc.update({
        "state_version": int(doc.get("state_version") or 1),
        "state_transition_log": doc.get("state_transition_log") or [
            _incident_transition_entry(
                from_status=None,
                to_status=status,
                actor="system:identity",
                reason="incident discovered by identity engine",
            )
        ],
        "updated_at": now,
    })
    return doc

async def _persist_identity_incidents(threats: List[Dict[str, Any]]) -> None:
    db = get_db()
    if db is None:
        return
    for threat in threats:
        doc = _incident_doc_from_threat(threat)
        await db[IDENTITY_INCIDENT_COLLECTION].update_one(
            {"id": doc.get("id")},
            {"$set": doc, "$setOnInsert": {"created_at": datetime.now(timezone.utc).isoformat()}},
            upsert=True,
        )

async def _get_incident_record(incident_id: str) -> Dict[str, Any]:
    db = get_db()
    if db is None:
        return {}
    return await db[IDENTITY_INCIDENT_COLLECTION].find_one({"id": incident_id}, {"_id": 0}) or {}

async def _ensure_incident_state_fields(incident_id: str, *, actor: str, reason: str) -> Dict[str, Any]:
    db = get_db()
    if db is None:
        return {}
    incident = await db[IDENTITY_INCIDENT_COLLECTION].find_one({"id": incident_id}, {"_id": 0})
    if not incident:
        return {}
    if incident.get("state_version") is not None and incident.get("state_transition_log") is not None:
        return incident
    current_status = str(incident.get("status") or "active")
    bootstrap = {
        "state_version": int(incident.get("state_version") or 1),
        "state_transition_log": incident.get("state_transition_log") or [
            _incident_transition_entry(
                from_status=None,
                to_status=current_status,
                actor=actor,
                reason=reason,
            )
        ],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    await db[IDENTITY_INCIDENT_COLLECTION].update_one({"id": incident_id}, {"$set": bootstrap})
    return await db[IDENTITY_INCIDENT_COLLECTION].find_one({"id": incident_id}, {"_id": 0}) or {}

async def _transition_incident_status(
    incident_id: str,
    *,
    expected_statuses: List[str],
    next_status: str,
    actor: str,
    reason: str,
    expected_state_version: Optional[int] = None,
    transition_metadata: Optional[Dict[str, Any]] = None,
    extra_updates: Optional[Dict[str, Any]] = None,
) -> bool:
    db = get_db()
    if db is None:
        return False
    incident = await db[IDENTITY_INCIDENT_COLLECTION].find_one({"id": incident_id}, {"_id": 0})
    if not incident:
        return False
    from_status = str(incident.get("status") or "").lower().strip()
    if from_status not in expected_statuses:
        return False
    resolved_version = expected_state_version
    if resolved_version is None:
        resolved_version = int(incident.get("state_version") or 0)
    query: Dict[str, Any] = {
        "id": incident_id,
        "status": {"$in": expected_statuses},
    }
    if resolved_version <= 0:
        query["$or"] = [{"state_version": {"$exists": False}}, {"state_version": 0}]
    else:
        query["state_version"] = resolved_version
    set_doc = {
        "status": next_status,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    if extra_updates:
        set_doc.update(extra_updates)
    result = await db[IDENTITY_INCIDENT_COLLECTION].update_one(
        query,
        {
            "$set": set_doc,
            "$inc": {"state_version": 1},
            "$push": {
                "state_transition_log": _incident_transition_entry(
                    from_status=from_status,
                    to_status=next_status,
                    actor=actor,
                    reason=reason,
                    metadata=transition_metadata,
                )
            },
        },
    )
    return bool(getattr(result, "modified_count", 0))

router = APIRouter(prefix="/api/v1/identity", tags=["Identity Protection"])
verify_identity_ingest_token = require_machine_token(
    env_keys=["IDENTITY_INGEST_TOKEN", "INTEGRATION_API_KEY", "SWARM_AGENT_TOKEN"],
    header_names=["x-identity-token", "x-internal-token", "x-agent-token"],
    subject="identity ingest",
)


class IdentityScanRequest(BaseModel):
    include_kerberos: bool = True
    include_ldap: bool = True
    include_ntlm: bool = True


class IdentityProviderEventIngestRequest(BaseModel):
    events: List[Dict[str, Any]]


class IdentityResponseActionRequest(BaseModel):
    action: str
    user: Optional[str] = None
    session_id: Optional[str] = None
    token_id: Optional[str] = None
    provider: Optional[str] = None
    reason: Optional[str] = None
    requested_by: str = "system"
    metadata: Dict[str, Any] = {}


def _safe_iso(value: Any) -> str:
    if isinstance(value, str) and value.strip():
        normalized = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()
    if hasattr(value, "isoformat"):
        try:
            parsed = value
            if getattr(parsed, "tzinfo", None) is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()
    return datetime.now(timezone.utc).isoformat()


def _normalize_identity_provider_event(provider: str, event: Dict[str, Any]) -> Dict[str, Any]:
    lower_provider = (provider or "unknown").strip().lower()
    event_id = str(
        event.get("event_id")
        or event.get("id")
        or event.get("uuid")
        or f"{lower_provider}-{datetime.now(timezone.utc).timestamp()}"
    )
    event_type = str(
        event.get("event_type")
        or event.get("type")
        or event.get("activityDisplayName")
        or event.get("operationName")
        or "unknown"
    )
    timestamp = _safe_iso(
        event.get("timestamp")
        or event.get("createdDateTime")
        or event.get("published")
        or event.get("time")
    )
    user = str(
        event.get("user")
        or event.get("userPrincipalName")
        or event.get("user_id")
        or event.get("actor")
        or "unknown"
    ).lower()
    source_ip = str(
        event.get("source_ip")
        or event.get("ipAddress")
        or event.get("client_ip")
        or event.get("ip")
        or "unknown"
    )
    status = str(
        event.get("status")
        or event.get("result")
        or event.get("outcome")
        or "unknown"
    ).lower()
    token_id = str(
        event.get("token_id")
        or event.get("tokenId")
        or event.get("refresh_token_id")
        or event.get("access_token_id")
        or ""
    )
    session_id = str(
        event.get("session_id")
        or event.get("sessionId")
        or event.get("correlationId")
        or event.get("requestId")
        or ""
    )
    app_id = str(event.get("app_id") or event.get("appId") or event.get("client_id") or "")
    resource = str(event.get("resource") or event.get("resourceDisplayName") or event.get("audience") or "")
    risk_score = event.get("risk_score") or event.get("riskScore") or event.get("risk_level") or 0
    geo_country = str(
        event.get("geo_country")
        or event.get("country")
        or event.get("countryCode")
        or ((event.get("location") or {}).get("countryOrRegion") if isinstance(event.get("location"), dict) else "")
        or ""
    ).upper()
    geo_asn = str(event.get("geo_asn") or event.get("asn") or event.get("autonomousSystemNumber") or "")
    location = event.get("location") if isinstance(event.get("location"), dict) else {}
    latitude = event.get("latitude") or event.get("lat") or location.get("latitude")
    longitude = event.get("longitude") or event.get("lon") or location.get("longitude")
    try:
        risk_score = int(risk_score)
    except Exception:
        risk_score = 0

    return {
        "provider": lower_provider,
        "event_id": event_id,
        "event_type": event_type,
        "timestamp": timestamp,
        "user": user,
        "source_ip": source_ip,
        "status": status,
        "token_id": token_id,
        "session_id": session_id,
        "app_id": app_id,
        "resource": resource,
        "risk_score": risk_score,
        "geo_country": geo_country,
        "geo_asn": geo_asn,
        "latitude": latitude,
        "longitude": longitude,
        "raw": event,
    }


def _normalize_identity_response_action(request: IdentityResponseActionRequest) -> Dict[str, Any]:
    action = (request.action or "").strip().lower()
    provider = (request.provider or "unknown").strip().lower()
    now_iso = datetime.now(timezone.utc).isoformat()
    action_id = f"identity-action-{int(datetime.now(timezone.utc).timestamp() * 1000)}"

    return {
        "action_id": action_id,
        "action": action,
        "provider": provider,
        "user": (request.user or "").strip().lower() or None,
        "session_id": (request.session_id or "").strip() or None,
        "token_id": (request.token_id or "").strip() or None,
        "reason": request.reason or "manual identity response action",
        "requested_by": (request.requested_by or "system").strip(),
        "metadata": request.metadata or {},
        "status": "queued",
        "created_at": now_iso,
        "updated_at": now_iso,
    }


async def _persist_identity_provider_events(events: List[Dict[str, Any]]) -> None:
    if not events:
        return
    db = get_db()
    if db is not None:
        for event in events:
            await db[IDENTITY_EVENT_COLLECTION].update_one(
                {"provider": event.get("provider"), "event_id": event.get("event_id")},
                {
                    "$set": event,
                    "$setOnInsert": {
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    },
                },
                upsert=True,
            )
        return

    _identity_event_cache.extend(events)
    if len(_identity_event_cache) > _IDENTITY_EVENT_CACHE_LIMIT:
        overflow = len(_identity_event_cache) - _IDENTITY_EVENT_CACHE_LIMIT
        del _identity_event_cache[:overflow]


async def _query_identity_provider_events(since_iso: str, provider: Optional[str] = None) -> List[Dict[str, Any]]:
    db = get_db()
    if db is not None:
        query: Dict[str, Any] = {"timestamp": {"$gte": since_iso}}
        if provider:
            query["provider"] = provider.strip().lower()
        return await db[IDENTITY_EVENT_COLLECTION].find(query, {"_id": 0}).to_list(10000)

    normalized_provider = provider.strip().lower() if provider else None
    out: List[Dict[str, Any]] = []
    for event in _identity_event_cache:
        if normalized_provider and event.get("provider") != normalized_provider:
            continue
        if str(event.get("timestamp") or "") >= since_iso:
            out.append(event)
    return out


async def _persist_identity_response_action(action_doc: Dict[str, Any]) -> None:
    db = get_db()
    if db is not None:
        await db[IDENTITY_RESPONSE_ACTION_COLLECTION].update_one(
            {"action_id": action_doc.get("action_id")},
            {
                "$set": action_doc,
                "$setOnInsert": {
                    "created_at": action_doc.get("created_at") or datetime.now(timezone.utc).isoformat(),
                },
            },
            upsert=True,
        )
        return

    _identity_response_action_cache.append(action_doc)
    if len(_identity_response_action_cache) > _IDENTITY_RESPONSE_ACTION_CACHE_LIMIT:
        overflow = len(_identity_response_action_cache) - _IDENTITY_RESPONSE_ACTION_CACHE_LIMIT
        del _identity_response_action_cache[:overflow]


async def _list_identity_response_actions(limit: int = 50) -> List[Dict[str, Any]]:
    db = get_db()
    if db is not None:
        docs = await db[IDENTITY_RESPONSE_ACTION_COLLECTION].find({}, {"_id": 0}).to_list(5000)
        docs.sort(key=lambda d: str(d.get("created_at") or ""), reverse=True)
        return docs[:limit]
    return list(reversed(_identity_response_action_cache[-limit:]))


def _build_response_hints(action_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    action = str(action_doc.get("action") or "").strip().lower()
    user = action_doc.get("user")
    provider = action_doc.get("provider")

    if action == "revoke_session":
        return [
            {
                "type": "soar",
                "action": "disable_user",
                "parameters": {"user": user, "provider": provider},
                "description": "Disable account if repeated malicious session behavior continues",
            }
        ]
    if action == "revoke_token":
        return [
            {
                "type": "soar",
                "action": "rotate_credentials",
                "parameters": {"user": user, "provider": provider},
                "description": "Rotate user credentials and invalidate refresh/access tokens",
            }
        ]
    if action == "disable_user":
        return [
            {
                "type": "soar",
                "action": "send_alert",
                "parameters": {"severity": "high", "message": f"Identity account disabled: {user or 'unknown'}"},
                "description": "Notify SOC and identity admins of account disable action",
            }
        ]
    return []


def _is_failure_status(status: str) -> bool:
    normalized = (status or "").strip().lower()
    if not normalized:
        return False
    return normalized in {"failure", "failed", "deny", "denied", "error", "blocked"}


def _safe_parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    try:
        text = str(value).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _ip_region_key(ip: str) -> str:
    text = (ip or "").strip()
    if not text or text == "unknown":
        return "unknown"
    try:
        obj = ipaddress.ip_address(text)
        if obj.version == 4:
            parts = text.split(".")
            return ".".join(parts[:2]) if len(parts) >= 2 else text
        # IPv6 coarse region key: first 3 hextets
        hextets = obj.exploded.split(":")
        return ":".join(hextets[:3])
    except Exception:
        return text


def _safe_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(value)
    except Exception:
        return None


def _extract_geo_point(event: Dict[str, Any]) -> Optional[Dict[str, float]]:
    raw = event.get("raw") if isinstance(event, dict) else None
    lat = _safe_float(event.get("latitude"))
    lon = _safe_float(event.get("longitude"))

    if lat is None and isinstance(raw, dict):
        lat = _safe_float(raw.get("latitude") or raw.get("lat") or (raw.get("location") or {}).get("latitude"))
    if lon is None and isinstance(raw, dict):
        lon = _safe_float(raw.get("longitude") or raw.get("lon") or (raw.get("location") or {}).get("longitude"))

    if lat is None or lon is None:
        return None
    return {"latitude": lat, "longitude": lon}


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    from math import radians, sin, cos, asin, sqrt

    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    c = 2 * asin(sqrt(a))
    return 6371.0 * c


def _confidence_label(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 65:
        return "medium"
    return "low"


def _compute_impossible_travel_candidates(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_user: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for event in events:
        user = str(event.get("user") or "unknown").strip().lower()
        by_user[user].append(event)

    candidates: List[Dict[str, Any]] = []
    for user, user_events in by_user.items():
        ordered = sorted(
            user_events,
            key=lambda e: _safe_parse_dt(e.get("timestamp")) or datetime.fromtimestamp(0, tz=timezone.utc),
        )
        for prev, curr in zip(ordered, ordered[1:]):
            prev_ip = str(prev.get("source_ip") or "unknown").strip()
            curr_ip = str(curr.get("source_ip") or "unknown").strip()
            if not prev_ip or not curr_ip or prev_ip == curr_ip:
                continue

            prev_dt = _safe_parse_dt(prev.get("timestamp"))
            curr_dt = _safe_parse_dt(curr.get("timestamp"))
            if prev_dt is None or curr_dt is None:
                continue

            delta_minutes = int(abs((curr_dt - prev_dt).total_seconds()) // 60)
            if delta_minutes > 30:
                continue

            prev_region = _ip_region_key(prev_ip)
            curr_region = _ip_region_key(curr_ip)
            if prev_region == curr_region:
                continue

            prev_country = str(prev.get("geo_country") or "").strip().upper()
            curr_country = str(curr.get("geo_country") or "").strip().upper()
            prev_asn = str(prev.get("geo_asn") or "").strip().upper()
            curr_asn = str(curr.get("geo_asn") or "").strip().upper()
            country_changed = bool(prev_country and curr_country and prev_country != curr_country)
            asn_changed = bool(prev_asn and curr_asn and prev_asn != curr_asn)

            prev_token = str(prev.get("token_id") or "").strip()
            curr_token = str(curr.get("token_id") or "").strip()
            prev_session = str(prev.get("session_id") or "").strip()
            curr_session = str(curr.get("session_id") or "").strip()

            token_continuity = bool(prev_token and curr_token and prev_token == curr_token)
            session_continuity = bool(prev_session and curr_session and prev_session == curr_session)
            confidence = 35
            if country_changed:
                confidence += 25
            else:
                confidence += 10
            if asn_changed:
                confidence += 20
            if token_continuity:
                confidence += 20
            if session_continuity:
                confidence += 15
            if delta_minutes <= 10:
                confidence += 10
            elif delta_minutes <= 20:
                confidence += 5

            distance_km: Optional[float] = None
            speed_kmh: Optional[float] = None
            prev_geo = _extract_geo_point(prev)
            curr_geo = _extract_geo_point(curr)
            if prev_geo and curr_geo and delta_minutes > 0:
                distance_km = _haversine_km(
                    prev_geo["latitude"],
                    prev_geo["longitude"],
                    curr_geo["latitude"],
                    curr_geo["longitude"],
                )
                speed_kmh = distance_km / (delta_minutes / 60)
                if speed_kmh >= 900:
                    confidence += 20
                elif speed_kmh >= 500:
                    confidence += 10

            risk = min(max(confidence, 0), 100)

            candidates.append(
                {
                    "user": user,
                    "from_ip": prev_ip,
                    "to_ip": curr_ip,
                    "from_timestamp": prev_dt.isoformat(),
                    "to_timestamp": curr_dt.isoformat(),
                    "minutes_between": delta_minutes,
                    "from_region": prev_region,
                    "to_region": curr_region,
                    "from_country": prev_country or None,
                    "to_country": curr_country or None,
                    "country_changed": country_changed,
                    "from_asn": prev_asn or None,
                    "to_asn": curr_asn or None,
                    "asn_changed": asn_changed,
                    "token_continuity": token_continuity,
                    "session_continuity": session_continuity,
                    "distance_km": round(distance_km, 2) if distance_km is not None else None,
                    "estimated_speed_kmh": round(speed_kmh, 2) if speed_kmh is not None else None,
                    "confidence_score": risk,
                    "confidence_level": _confidence_label(risk),
                    "risk_score": min(risk, 100),
                }
            )

    return candidates


def _compute_token_abuse_findings(events: List[Dict[str, Any]], lookback_hours: int) -> Dict[str, Any]:
    token_ips: Dict[str, set] = defaultdict(set)
    token_users: Dict[str, set] = defaultdict(set)
    session_ips: Dict[str, set] = defaultdict(set)
    user_tokens: Dict[str, set] = defaultdict(set)
    failed_auth_events = 0
    high_risk_events = 0

    for event in events:
        token_id = str(event.get("token_id") or "").strip()
        user = str(event.get("user") or "unknown").strip().lower()
        source_ip = str(event.get("source_ip") or "unknown").strip()
        session_id = str(event.get("session_id") or "").strip()
        status = str(event.get("status") or "").strip().lower()
        risk_score = int(event.get("risk_score") or 0)

        if token_id:
            token_ips[token_id].add(source_ip)
            token_users[token_id].add(user)
            user_tokens[user].add(token_id)
        if session_id:
            session_ips[session_id].add(source_ip)
        if _is_failure_status(status):
            failed_auth_events += 1
        if risk_score >= 70:
            high_risk_events += 1

    token_reuse_multi_ip = [
        {
            "token_id": token_id,
            "distinct_ips": sorted(list(ips)),
            "ip_count": len(ips),
            "users": sorted(list(token_users.get(token_id, set()))),
        }
        for token_id, ips in token_ips.items()
        if len(ips) >= 2
    ]

    session_reuse_multi_ip = [
        {
            "session_id": session_id,
            "distinct_ips": sorted(list(ips)),
            "ip_count": len(ips),
        }
        for session_id, ips in session_ips.items()
        if len(ips) >= 2
    ]

    token_spray_by_user = [
        {
            "user": user,
            "token_count": len(tokens),
            "token_ids": sorted(list(tokens))[:20],
        }
        for user, tokens in user_tokens.items()
        if len(tokens) >= 5
    ]

    impossible_travel_candidates = _compute_impossible_travel_candidates(events)

    findings_count = (
        len(token_reuse_multi_ip)
        + len(session_reuse_multi_ip)
        + len(token_spray_by_user)
        + len(impossible_travel_candidates)
    )
    return {
        "lookback_hours": lookback_hours,
        "events_analyzed": len(events),
        "findings_count": findings_count,
        "failed_auth_events": failed_auth_events,
        "high_risk_events": high_risk_events,
        "token_reuse_multi_ip": token_reuse_multi_ip,
        "session_reuse_multi_ip": session_reuse_multi_ip,
        "token_spray_by_user": token_spray_by_user,
        "impossible_travel_candidates": impossible_travel_candidates,
    }


def _build_impossible_travel_action(candidate: Dict[str, Any], provider: Optional[str]) -> Dict[str, Any]:
    now_iso = datetime.now(timezone.utc).isoformat()
    confidence = int(candidate.get("confidence_score") or candidate.get("risk_score") or 0)
    action = "revoke_session" if candidate.get("session_continuity") else "revoke_token"
    if confidence >= 95 and candidate.get("token_continuity"):
        action = "disable_user"

    signature = (
        f"impossible-travel|{candidate.get('user')}|{candidate.get('from_ip')}|"
        f"{candidate.get('to_ip')}|{candidate.get('to_timestamp')}"
    )
    return {
        "action_id": f"identity-action-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
        "action": action,
        "provider": (provider or "unknown").strip().lower(),
        "user": candidate.get("user"),
        "session_id": None,
        "token_id": None,
        "reason": "auto-dispatch policy: high-confidence impossible travel",
        "requested_by": "identity-auto-dispatch-policy",
        "metadata": {
            "policy": "impossible_travel_auto_dispatch",
            "policy_signature": signature,
            "candidate": {
                "from_ip": candidate.get("from_ip"),
                "to_ip": candidate.get("to_ip"),
                "minutes_between": candidate.get("minutes_between"),
                "confidence_score": confidence,
                "token_continuity": candidate.get("token_continuity"),
                "session_continuity": candidate.get("session_continuity"),
            },
        },
        "status": "queued",
        "created_at": now_iso,
        "updated_at": now_iso,
    }


async def _find_identity_response_action_by_policy_signature(signature: str) -> Optional[Dict[str, Any]]:
    db = get_db()
    if db is not None:
        return await db[IDENTITY_RESPONSE_ACTION_COLLECTION].find_one(
            {"metadata.policy_signature": signature},
            {"_id": 0},
        )
    for action in reversed(_identity_response_action_cache):
        meta = action.get("metadata") or {}
        if meta.get("policy_signature") == signature:
            return action
    return None


async def _find_identity_response_action(action_id: str) -> Optional[Dict[str, Any]]:
    db = get_db()
    if db is not None:
        return await db[IDENTITY_RESPONSE_ACTION_COLLECTION].find_one({"action_id": action_id}, {"_id": 0})
    for action in reversed(_identity_response_action_cache):
        if str(action.get("action_id")) == action_id:
            return action
    return None


async def _update_identity_response_action_status(
    action_id: str,
    *,
    status: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    now_iso = datetime.now(timezone.utc).isoformat()
    updates: Dict[str, Any] = {
        "status": status,
        "updated_at": now_iso,
    }
    if metadata:
        updates["dispatch"] = metadata

    db = get_db()
    if db is not None:
        await db[IDENTITY_RESPONSE_ACTION_COLLECTION].update_one({"action_id": action_id}, {"$set": updates})
        return

    for action in _identity_response_action_cache:
        if str(action.get("action_id")) == action_id:
            action.update(updates)
            return


def _build_soar_trigger_event(action_doc: Dict[str, Any]) -> Dict[str, Any]:
    action = str(action_doc.get("action") or "").strip().lower()
    trigger_type = "rapid_credential_access"
    if action not in {"revoke_session", "revoke_token", "rotate_credentials", "disable_user"}:
        trigger_type = "anomaly_detected"

    return {
        "trigger_type": trigger_type,
        "severity": "high",
        "machine_likelihood": "high",
        "intents": "credential_access",
        "source_ip": action_doc.get("metadata", {}).get("source_ip") or "unknown",
        "agent_id": action_doc.get("metadata", {}).get("agent_id") or "identity-service",
        "extra": {
            "identity_action_id": action_doc.get("action_id"),
            "identity_action": action,
            "provider": action_doc.get("provider"),
            "user": action_doc.get("user"),
            "session_id": action_doc.get("session_id"),
            "token_id": action_doc.get("token_id"),
            "reason": action_doc.get("reason"),
            "requested_by": action_doc.get("requested_by"),
            "metadata": action_doc.get("metadata") or {},
        },
    }


async def _dispatch_identity_action_doc(action_doc: Dict[str, Any]) -> Dict[str, Any]:
    action_id = str(action_doc.get("action_id") or "")
    db = get_db()
    actor = str(action_doc.get("requested_by") or "identity-service")
    gated: Dict[str, Any] = {}
    try:
        gate = OutboundGateService(db)
        gated = await gate.gate_action(
            action_type="response_execution",
            actor=actor,
            payload=action_doc,
            impact_level="critical",
            subject_id=str(action_doc.get("user") or action_doc.get("provider") or action_id or "identity-action"),
            entity_refs=[action_id, str(action_doc.get("user") or ""), str(action_doc.get("provider") or "")],
            requires_triune=True,
        )
        try:
            await emit_world_event(
                db,
                event_type="identity_response_action_dispatch_gated",
                entity_refs=[action_id, gated.get("queue_id"), gated.get("decision_id")],
                payload={"action": action_doc.get("action"), "requested_by": actor},
                trigger_triune=True,
            )
        except Exception:
            pass
    except Exception:
        # Keep response actions functional even when outbound-gate persistence is unavailable.
        gated = {}

    metadata = action_doc.get("metadata") or {}
    force_no_match = bool(metadata.get("force_no_match"))
    executions: List[Dict[str, Any]] = []
    status = "no_matching_playbook" if force_no_match else "dispatched"
    if not force_no_match:
        executions.append(
            {
                "execution_id": f"exec-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
                "playbook_id": "identity-remediate",
                "status": "queued",
                "queued_at": datetime.now(timezone.utc).isoformat(),
            }
        )

    dispatch_meta = {
        "queue_id": gated.get("queue_id"),
        "decision_id": gated.get("decision_id"),
        "action_type": "response_execution",
        "executions_count": len(executions),
    }
    await _update_identity_response_action_status(action_id, status=status, metadata=dispatch_meta)
    try:
        await emit_world_event(
            db,
            event_type="identity_response_action_dispatched" if status == "dispatched" else "identity_response_action_no_matching_playbook",
            entity_refs=[action_id, gated.get("queue_id"), gated.get("decision_id")],
            payload={"action": action_doc.get("action"), "requested_by": actor, "status": status},
            trigger_triune=False,
        )
    except Exception:
        pass
    return {
        "status": status,
        "action_id": action_id,
        "queue_id": gated.get("queue_id"),
        "decision_id": gated.get("decision_id"),
        "executions": executions,
        "executions_count": len(executions),
    }


async def _run_identity_auto_dispatch_policy(
    analytics: Dict[str, Any],
    provider: Optional[str],
    min_confidence: int,
    dry_run: bool,
) -> Dict[str, Any]:
    candidates = analytics.get("impossible_travel_candidates") or []
    selected = [
        c
        for c in candidates
        if int(c.get("confidence_score") or c.get("risk_score") or 0) >= min_confidence
    ]

    created: List[Dict[str, Any]] = []
    dispatched: List[Dict[str, Any]] = []
    skipped_existing = 0
    for candidate in selected:
        action_doc = _build_impossible_travel_action(candidate, provider=provider)
        signature = (action_doc.get("metadata") or {}).get("policy_signature")
        if signature:
            existing = await _find_identity_response_action_by_policy_signature(signature)
            if existing:
                skipped_existing += 1
                continue

        if dry_run:
            created.append(action_doc)
            continue

        await _persist_identity_response_action(action_doc)
        created.append(action_doc)
        try:
            dispatch_result = await _dispatch_identity_action_doc(action_doc)
            dispatched.append(dispatch_result)
        except Exception as e:
            await _update_identity_response_action_status(
                str(action_doc.get("action_id") or ""),
                status="dispatch_error",
                metadata={"error": str(e), "policy": "impossible_travel_auto_dispatch"},
            )

    return {
        "enabled": True,
        "policy": "impossible_travel_auto_dispatch",
        "dry_run": dry_run,
        "min_confidence": min_confidence,
        "eligible_candidates": len(selected),
        "created_actions_count": len(created),
        "dispatched_count": len([d for d in dispatched if d.get("status") == "dispatched"]),
        "no_matching_playbook_count": len([d for d in dispatched if d.get("status") == "no_matching_playbook"]),
        "skipped_existing_count": skipped_existing,
        "created_action_ids": [a.get("action_id") for a in created],
    }


def _to_iso(value: Any) -> str:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return datetime.now(timezone.utc).isoformat()


def _normalize_threat(threat: Dict[str, Any]) -> Dict[str, Any]:
    mitre = threat.get("mitre_techniques") or []
    return {
        "id": threat.get("event_id"),
        "type": threat.get("attack_type", "unknown"),
        "severity": threat.get("severity", "medium"),
        "source_user": threat.get("evidence", {}).get("source_user") or threat.get("source_ip", "unknown"),
        "target": threat.get("target_principal", "unknown"),
        "timestamp": _to_iso(threat.get("timestamp")),
        "mitre": mitre[0] if mitre else "",
        "status": "active",
        "details": threat.get("description", ""),
        "raw": threat,
    }


@router.get("/stats")
async def get_identity_stats() -> Dict[str, Any]:
    engine = get_identity_protection_engine()
    summary = engine.get_threat_summary()
    det_health = engine.get_detector_health()

    kerberos_stats = det_health.get("detectors", {}).get("kerberos", {}).get("stats", {})
    credential_stats = det_health.get("detectors", {}).get("credential", {}).get("stats", {})

    return {
        "total_users": kerberos_stats.get("unique_users_tracked", 0),
        "privileged_accounts": credential_stats.get("privileged_accounts_monitored", 0),
        "active_threats": summary.get("active_threats", 0),
        "blocked_attacks": summary.get("metrics", {}).get("auto_responses_triggered", 0),
        "kerberos_anomalies": summary.get("attack_type_distribution", {}).get("kerberoasting", 0),
        "credential_dumps": summary.get("attack_type_distribution", {}).get("credential_dumping", 0),
        "summary": summary,
    }


@router.get("/threats")
async def get_identity_threats(limit: int = Query(50, ge=1, le=500)) -> Dict[str, Any]:
    db = get_db()
    if db is not None:
        docs = await db[IDENTITY_INCIDENT_COLLECTION].find({}, {"_id": 0}).to_list(5000)
        docs.sort(key=lambda d: (d.get("severity", "medium"), d.get("timestamp", "")), reverse=True)
        total = len(docs)
        docs = docs[:limit]
        return {
            "threats": docs,
            "count": total,
        }

    # Fallback to in-memory engine
    engine = get_identity_protection_engine()
    active = engine.get_active_threats()
    history = [_normalize_threat(t) for t in active]
    if len(history) < limit:
        more = [_normalize_threat(t) for t in [t.__dict__ if hasattr(t, "__dict__") else t for t in engine.threat_history[-limit:]]]
        seen = {h["id"] for h in history}
        for item in reversed(more):
            if item["id"] not in seen:
                history.append(item)
                seen.add(item["id"])
            if len(history) >= limit:
                break
    return {
        "threats": history[:limit],
        "count": len(history[:limit]),
    }
@router.get("/incident/{incident_id}")
async def get_identity_incident(incident_id: str) -> Dict[str, Any]:
    durable = await _get_incident_record(incident_id)
    if durable:
        return durable
    engine = get_identity_protection_engine()
    for t in engine.get_active_threats():
        norm = _normalize_threat(t)
        if norm["id"] == incident_id:
            return norm
    for t in engine.threat_history:
        norm = _normalize_threat(t.__dict__ if hasattr(t, "__dict__") else t)
        if norm["id"] == incident_id:
            return norm
    return {}
class IncidentStatusUpdate(BaseModel):
    status: str
    reason: Optional[str] = None
    updated_by: Optional[str] = None

@router.post("/incident/{incident_id}/status")
async def update_identity_incident_status(
    incident_id: str,
    update: IncidentStatusUpdate,
    current_user: dict = Depends(check_permission("write")),
) -> Dict[str, Any]:
    if update.status == "suppressed" and not update.reason:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Reason required for suppression")

    db = get_db()
    actor = current_user.get("email", current_user.get("id", "unknown")) if isinstance(current_user, dict) else "unknown"
    if db is not None:
        incident = await _ensure_incident_state_fields(
            incident_id,
            actor=actor,
            reason="bootstrap identity incident durability fields",
        )
        if not incident:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Incident not found")
        current_status = str(incident.get("status") or "active")
        target_status = update.status
        if current_status == target_status:
            from fastapi import HTTPException
            raise HTTPException(status_code=409, detail=f"Incident already in status={target_status}")
        allowed_targets = {
            "active": {"in_progress", "resolved", "suppressed", "false_positive"},
            "in_progress": {"resolved", "suppressed", "false_positive"},
        }
        if current_status in IDENTITY_INCIDENT_TERMINAL_STATUSES:
            from fastapi import HTTPException
            raise HTTPException(status_code=409, detail=f"Incident already terminal (status={current_status})")
        if target_status not in allowed_targets.get(current_status, set()):
            from fastapi import HTTPException
            raise HTTPException(
                status_code=409,
                detail=f"Invalid incident transition {current_status} -> {target_status}",
            )
        reason = update.reason or f"status updated to {target_status}"
        extra_updates: Dict[str, Any] = {}
        evidence = dict(incident.get("evidence") or {})
        if target_status == "suppressed":
            evidence["suppression_reason"] = reason
            evidence["suppressed_by"] = actor
            evidence["suppressed_at"] = datetime.now(timezone.utc).isoformat()
        elif target_status == "resolved":
            evidence["resolution_note"] = reason
            evidence["resolved_at"] = datetime.now(timezone.utc).isoformat()
        if evidence:
            extra_updates["evidence"] = evidence
        transitioned = await _transition_incident_status(
            incident_id,
            expected_statuses=[current_status],
            next_status=target_status,
            actor=actor,
            reason=reason,
            expected_state_version=int(incident.get("state_version") or 0),
            transition_metadata={"updated_by": update.updated_by or actor},
            extra_updates=extra_updates,
        )
        if not transitioned:
            refreshed = await _get_incident_record(incident_id)
            if not refreshed:
                from fastapi import HTTPException
                raise HTTPException(status_code=404, detail="Incident not found")
            if str(refreshed.get("status") or "") == target_status:
                from fastapi import HTTPException
                raise HTTPException(status_code=409, detail=f"Incident already in status={target_status}")
            from fastapi import HTTPException
            raise HTTPException(status_code=409, detail="Incident update conflict; state changed concurrently")
        updated_at = datetime.now(timezone.utc).isoformat()
        await emit_world_event(get_db(), event_type="identity_incident_status_updated", entity_refs=[incident_id], payload={"status": target_status, "actor": actor, "reason": reason}, trigger_triune=False)
        return {
            "incident_id": incident_id,
            "status": target_status,
            "updated_at": updated_at,
        }

    # Fallback in-memory path
    engine = get_identity_protection_engine()
    found = None
    for t in engine.get_active_threats():
        norm = _normalize_threat(t)
        if norm["id"] == incident_id:
            found = norm
            break
    if not found:
        for t in engine.threat_history:
            norm = _normalize_threat(t.__dict__ if hasattr(t, "__dict__") else t)
            if norm["id"] == incident_id:
                found = norm
                break
    if not found:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Incident not found")
    found["status"] = update.status
    return {
        "incident_id": incident_id,
        "status": update.status,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/alerts")
async def get_identity_alerts(limit: int = Query(100, ge=1, le=500)) -> Dict[str, Any]:
    threats_resp = await get_identity_threats(limit=limit)
    alerts: List[Dict[str, Any]] = []

    for t in threats_resp["threats"]:
        alerts.append({
            "id": t["id"],
            "severity": t["severity"],
            "message": t["details"] or f"Identity threat: {t['type']}",
            "user": t.get("source_user", "unknown"),
            "endpoint": t.get("target", "unknown"),
            "timestamp": t.get("timestamp"),
            "type": t.get("type"),
        })

    return {
        "alerts": alerts,
        "count": len(alerts),
    }


@router.post("/scan")
async def run_identity_scan(
    request: Optional[IdentityScanRequest] = None,
    current_user: dict = Depends(check_permission("write")),
) -> Dict[str, Any]:
    # The identity engine is event-driven; this endpoint returns a compatible scan trigger response.
    _ = request
    engine = get_identity_protection_engine()
    summary = engine.get_threat_summary()
    scan_id = f"identity-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    timestamp = datetime.now(timezone.utc).isoformat()
    await emit_world_event(get_db(), event_type="identity_scan_completed", entity_refs=[scan_id], payload={"active_threats": summary.get("active_threats", 0), "threats_last_hour": summary.get("threats_last_hour", 0)}, trigger_triune=False)
    return {
        "status": "completed",
        "scan_id": scan_id,
        "timestamp": timestamp,
        "active_threats": summary.get("active_threats", 0),
        "threats_last_hour": summary.get("threats_last_hour", 0),
    }


@router.post("/events/entra")
async def ingest_entra_events(
    request: IdentityProviderEventIngestRequest,
    auth: dict = Depends(verify_identity_ingest_token),
) -> Dict[str, Any]:
    normalized_events = [_normalize_identity_provider_event("entra", event) for event in request.events]
    await _persist_identity_provider_events(normalized_events)
    await emit_world_event(get_db(), event_type="identity_provider_events_ingested", entity_refs=["entra"], payload={"provider": "entra", "ingested": len(normalized_events)}, trigger_triune=False)
    return {
        "status": "ok",
        "provider": "entra",
        "ingested": len(normalized_events),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/events/okta")
async def ingest_okta_events(
    request: IdentityProviderEventIngestRequest,
    auth: dict = Depends(verify_identity_ingest_token),
) -> Dict[str, Any]:
    normalized_events = [_normalize_identity_provider_event("okta", event) for event in request.events]
    await _persist_identity_provider_events(normalized_events)
    await emit_world_event(get_db(), event_type="identity_provider_events_ingested", entity_refs=["okta"], payload={"provider": "okta", "ingested": len(normalized_events)}, trigger_triune=False)
    return {
        "status": "ok",
        "provider": "okta",
        "ingested": len(normalized_events),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/events/m365-oauth-consents")
async def ingest_m365_oauth_consents(
    request: IdentityProviderEventIngestRequest,
    auth: dict = Depends(verify_identity_ingest_token),
) -> Dict[str, Any]:
    normalized_events = [_normalize_identity_provider_event("m365", event) for event in request.events]
    for event in normalized_events:
        raw = event.get("raw") or {}
        event_type = str(event.get("event_type") or "").lower()
        if any(keyword in event_type for keyword in ["consent", "oauth", "grant"]):
            event["risk_score"] = max(int(event.get("risk_score") or 0), 70)
            event["status"] = str(event.get("status") or "success")
        event["app_id"] = str(event.get("app_id") or raw.get("appId") or raw.get("clientId") or "")
        event["resource"] = str(event.get("resource") or raw.get("resourceDisplayName") or raw.get("scope") or "")
        event["geo_country"] = str(
            event.get("geo_country")
            or raw.get("country")
            or raw.get("countryCode")
            or ((raw.get("location") or {}).get("countryOrRegion") if isinstance(raw.get("location"), dict) else "")
            or ""
        ).upper()
        event["geo_asn"] = str(event.get("geo_asn") or raw.get("asn") or raw.get("autonomousSystemNumber") or "")
        event["latitude"] = event.get("latitude") or raw.get("latitude") or (raw.get("location") or {}).get("latitude")
        event["longitude"] = event.get("longitude") or raw.get("longitude") or (raw.get("location") or {}).get("longitude")

    await _persist_identity_provider_events(normalized_events)
    await emit_world_event(get_db(), event_type="identity_provider_events_ingested", entity_refs=["m365"], payload={"provider": "m365", "ingested": len(normalized_events)}, trigger_triune=False)
    return {
        "status": "ok",
        "provider": "m365",
        "ingested": len(normalized_events),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/analytics/token-abuse")
async def get_token_abuse_analytics(
    lookback_hours: int = Query(24, ge=1, le=168),
    provider: Optional[str] = Query(None),
    auto_dispatch: bool = Query(False),
    auto_dispatch_min_confidence: int = Query(85, ge=60, le=100),
    dry_run_dispatch: bool = Query(False),
    current_user: dict = Depends(get_current_user),
) -> Dict[str, Any]:
    resolved_auto_dispatch = auto_dispatch if isinstance(auto_dispatch, bool) else bool(getattr(auto_dispatch, "default", False))
    resolved_min_confidence = (
        int(auto_dispatch_min_confidence)
        if isinstance(auto_dispatch_min_confidence, int)
        else int(getattr(auto_dispatch_min_confidence, "default", 85))
    )
    resolved_dry_run = dry_run_dispatch if isinstance(dry_run_dispatch, bool) else bool(getattr(dry_run_dispatch, "default", False))

    since = datetime.now(timezone.utc).timestamp() - (lookback_hours * 3600)
    since_iso = datetime.fromtimestamp(since, tz=timezone.utc).isoformat()
    events = await _query_identity_provider_events(since_iso=since_iso, provider=provider)
    analytics = _compute_token_abuse_findings(events, lookback_hours=lookback_hours)
    analytics["provider_filter"] = provider.strip().lower() if provider else None
    analytics["generated_at"] = datetime.now(timezone.utc).isoformat()
    if resolved_auto_dispatch:
        analytics["auto_dispatch"] = await _run_identity_auto_dispatch_policy(
            analytics,
            provider=provider,
            min_confidence=resolved_min_confidence,
            dry_run=resolved_dry_run,
        )
    else:
        analytics["auto_dispatch"] = {
            "enabled": False,
            "policy": "impossible_travel_auto_dispatch",
            "dry_run": resolved_dry_run,
            "min_confidence": resolved_min_confidence,
        }
    return analytics


@router.post("/response/actions")
async def queue_identity_response_action(
    request: IdentityResponseActionRequest,
    current_user: dict = Depends(check_permission("write")),
) -> Dict[str, Any]:
    allowed_actions = {"revoke_session", "revoke_token", "disable_user", "rotate_credentials"}
    action = (request.action or "").strip().lower()
    if action not in allowed_actions:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"Unsupported identity response action '{request.action}'")

    action_doc = _normalize_identity_response_action(request)
    await _persist_identity_response_action(action_doc)
    actor = current_user.get("email", current_user.get("id", "unknown")) if isinstance(current_user, dict) else "unknown"
    try:
        await emit_world_event(
            get_db(),
            event_type="identity_response_action_queued",
            entity_refs=[action_doc.get("action_id", "")],
            payload={"action": action_doc.get("action"), "requested_by": actor},
            trigger_triune=None,
        )
    except Exception:
        pass

    return {
        "status": "queued",
        "action": action_doc,
        "soar_hints": _build_response_hints(action_doc),
    }


@router.get("/response/actions")
async def get_identity_response_actions(limit: int = Query(50, ge=1, le=500)) -> Dict[str, Any]:
    actions = await _list_identity_response_actions(limit=limit)
    return {
        "count": len(actions),
        "actions": actions,
    }


@router.post("/response/actions/{action_id}/dispatch")
async def dispatch_identity_response_action(
    action_id: str,
    dry_run: bool = Query(False),
    current_user: dict = Depends(check_permission("write")),
) -> Dict[str, Any]:
    action_doc = await _find_identity_response_action(action_id)
    if not action_doc:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Identity response action not found")

    trigger_event = _build_soar_trigger_event(action_doc)
    if dry_run:
        actor = current_user.get("email", current_user.get("id", "unknown")) if isinstance(current_user, dict) else "unknown"
        try:
            await emit_world_event(
                get_db(),
                event_type="identity_response_action_dispatch_requested",
                entity_refs=[action_id],
                payload={"dry_run": True, "actor": actor},
                trigger_triune=False,
            )
        except Exception:
            pass
        return {
            "status": "dry_run",
            "action_id": action_id,
            "trigger_event": trigger_event,
        }

    try:
        result = await _dispatch_identity_action_doc(action_doc)
        try:
            await emit_world_event(get_db(), event_type="identity_response_action_dispatched", entity_refs=[action_id], payload={"status": result.get("status")}, trigger_triune=False)
        except Exception:
            pass
        return result
    except Exception as e:
        await _update_identity_response_action_status(
            action_id,
            status="dispatch_error",
            metadata={"error": str(e), "trigger_event": trigger_event},
        )
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail=f"SOAR dispatch failed: {e}")
