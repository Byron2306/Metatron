from datetime import datetime, timezone
from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .dependencies import get_db, check_permission, get_current_user
from backend.services.governance_authority import GovernanceDecisionAuthority
from backend.services.governance_executor import GovernanceExecutorService

router = APIRouter(prefix="/governance", tags=["Governance"])


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DecisionApproveRequest(BaseModel):
    notes: Optional[str] = None
    execute_now: bool = True


class DecisionDenyRequest(BaseModel):
    reason: Optional[str] = None


class ExecutorRunRequest(BaseModel):
    limit: int = 100


@router.get("/decisions/pending")
async def get_pending_decisions(
    limit: int = 100,
    current_user: dict = Depends(get_current_user),
):
    db = get_db()
    docs = await db.triune_decisions.find(
        {"status": "pending"},
        {"_id": 0},
    ).sort("created_at", 1).limit(max(1, min(limit, 500))).to_list(max(1, min(limit, 500)))
    return {"count": len(docs), "items": docs}


@router.post("/decisions/{decision_id}/approve")
async def approve_decision(
    decision_id: str,
    request: DecisionApproveRequest,
    current_user: dict = Depends(check_permission("write")),
):
    db = get_db()
    decision = await db.triune_decisions.find_one({"decision_id": decision_id}, {"_id": 0})
    if not decision:
        raise HTTPException(status_code=404, detail="Decision not found")

    actor = current_user.get("email", current_user.get("id", "unknown"))
    authority = GovernanceDecisionAuthority(db)
    await authority.approve_decision(
        decision_id=decision_id,
        actor=actor,
        notes=request.notes,
        execution_status="pending_executor",
        source="governance_router",
    )

    execution_summary: Optional[Dict[str, Any]] = None
    if request.execute_now:
        execution_summary = await GovernanceExecutorService(db).process_approved_decisions(limit=100)

    return {
        "success": True,
        "decision_id": decision_id,
        "status": "approved",
        "execution_summary": execution_summary,
    }


@router.post("/decisions/{decision_id}/deny")
async def deny_decision(
    decision_id: str,
    request: DecisionDenyRequest,
    current_user: dict = Depends(check_permission("write")),
):
    db = get_db()
    decision = await db.triune_decisions.find_one({"decision_id": decision_id}, {"_id": 0})
    if not decision:
        raise HTTPException(status_code=404, detail="Decision not found")

    actor = current_user.get("email", current_user.get("id", "unknown"))
    authority = GovernanceDecisionAuthority(db)
    await authority.deny_decision(
        decision_id=decision_id,
        actor=actor,
        reason=request.reason,
        source="governance_router",
    )

    await db.agent_commands.update_many(
        {"decision_id": decision_id, "status": {"$in": ["gated_pending_approval", "pending_approval"]}},
        {
            "$set": {"status": "rejected", "updated_at": _iso_now(), "rejected_by": actor, "rejected_reason": request.reason},
            "$inc": {"state_version": 1},
            "$push": {
                "state_transition_log": {
                    "from_status": "gated_pending_approval",
                    "to_status": "rejected",
                    "actor": actor,
                    "reason": "triune decision denied",
                    "timestamp": _iso_now(),
                }
            },
        },
    )

    return {"success": True, "decision_id": decision_id, "status": "denied"}


@router.post("/executor/run-once")
async def run_executor_once(
    request: ExecutorRunRequest,
    current_user: dict = Depends(check_permission("write")),
):
    db = get_db()
    summary = await GovernanceExecutorService(db).process_approved_decisions(
        limit=max(1, min(request.limit, 500))
    )
    return {"success": True, "summary": summary}
