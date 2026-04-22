"""
Kernel Enforcement Router
=========================
Exposes ARDA's BPF LSM kernel enforcement layer controls.
The LSM must be loaded via bpf/build.sh --load (requires root + kernel 5.7+).

Sensor telemetry endpoints (sensors, events, capabilities) are handled by
the kernel_sensors.py router at /api/v1/kernel.

Endpoints:
  GET  /api/v1/kernel/status                       — LSM state (armed/mock/unavailable)
  POST /api/v1/kernel/workload/trust                — mark executable as harmonic (trusted)
  POST /api/v1/kernel/workload/distrust             — mark executable as fallen (blocked)
  GET  /api/v1/kernel/enforcement                   — get enforcement toggle state
  POST /api/v1/kernel/enforcement/{state}           — enable/disable enforcement (on/off)
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional

from .dependencies import get_current_user, check_permission

router = APIRouter(prefix="/kernel", tags=["Kernel Enforcement"])


class WorkloadTrustRequest(BaseModel):
    executable_path: str
    quantum_signature: Optional[dict] = None


class WorkloadDistrustRequest(BaseModel):
    executable_path: str


@router.get("/status")
async def get_kernel_status(current_user: dict = Depends(get_current_user)):
    """Return BPF LSM enforcement status."""
    import os as _os
    try:
        from services.os_enforcement_service import get_os_enforcement_service
        svc = get_os_enforcement_service()
        # Operator override: SERAPH_KERNEL_ENABLED=true reports sensor as active
        kernel_override = _os.environ.get("SERAPH_KERNEL_ENABLED", "").strip().lower() in ("1", "true", "yes")
        is_auth = svc.is_authoritative or kernel_override
        return {
            "is_authoritative": is_auth,
            "mode": "ring0_armed" if is_auth else "simulation",
            "bpf_source": getattr(svc, "bpf_source", None),
            "sovereign_mode": _os.environ.get("ARDA_SOVEREIGN_MODE", "0") == "1",
            "trusted_workloads": len(svc.lsm_map) if isinstance(svc.lsm_map, dict) else "hardware_map",
        }
    except Exception as e:
        return {"is_authoritative": False, "mode": "unavailable", "error": str(e)}


@router.post("/workload/trust")
async def trust_workload(
    req: WorkloadTrustRequest,
    current_user: dict = Depends(check_permission("manage_users")),
):
    """Mark an executable as harmonic (allowed) in the BPF LSM map."""
    try:
        from services.os_enforcement_service import get_os_enforcement_service
        svc = get_os_enforcement_service()
        result = svc.update_workload_harmony(
            executable_path=req.executable_path,
            is_harmonic=True,
            quantum_signature=req.quantum_signature,
        )
        if result is False:
            raise HTTPException(status_code=403, detail="BPF harmony update vetoed — check quantum signature and manifest")
        return {"status": "harmonic", "executable": req.executable_path}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/workload/distrust")
async def distrust_workload(
    req: WorkloadDistrustRequest,
    current_user: dict = Depends(check_permission("manage_users")),
):
    """Mark an executable as fallen (blocked) in the BPF LSM map."""
    try:
        from services.os_enforcement_service import get_os_enforcement_service
        svc = get_os_enforcement_service()
        svc.update_workload_harmony(
            executable_path=req.executable_path,
            is_harmonic=False,
        )
        return {"status": "fallen", "executable": req.executable_path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/enforcement")
async def get_enforcement_state(current_user: dict = Depends(get_current_user)):
    """Get current enforcement toggle state from BPF state map."""
    try:
        from services.os_enforcement_service import get_os_enforcement_service
        svc = get_os_enforcement_service()
        if not svc.is_authoritative:
            return {"enforcement": False, "reason": "LSM not loaded — operating in simulation mode"}
        state = svc.get_enforcement()
        if state is None:
            return {"enforcement": False, "reason": "state map not yet available"}
        return {"enforcement": state}
    except Exception as e:
        return {"enforcement": False, "error": str(e)}


@router.post("/enforcement/{state}")
async def set_enforcement(
    state: str,
    current_user: dict = Depends(check_permission("manage_users")),
):
    """Enable or disable BPF LSM enforcement. state must be 'on' or 'off'."""
    if state not in ("on", "off"):
        raise HTTPException(status_code=400, detail="state must be 'on' or 'off'")
    try:
        from services.os_enforcement_service import get_os_enforcement_service
        svc = get_os_enforcement_service()
        if not svc.is_authoritative:
            raise HTTPException(status_code=503, detail="LSM not loaded — cannot toggle enforcement")
        ok = svc.set_enforcement(state == "on")
        if not ok:
            raise HTTPException(status_code=500, detail="BPF map update failed")
        return {"enforcement": state == "on", "state": state}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
