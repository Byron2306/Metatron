"""
Quarantine Router
"""
from fastapi import APIRouter, HTTPException, Depends

from .dependencies import get_current_user, get_db

# Import quarantine service
from quarantine import (
    get_quarantine_summary, list_quarantined,
    get_quarantine_entry, restore_file, delete_quarantined
)

router = APIRouter(prefix="/quarantine", tags=["Quarantine"])

@router.get("")
async def get_quarantine_list(current_user: dict = Depends(get_current_user)):
    """Get all quarantined files"""
    return await list_quarantined()

@router.get("/summary")
async def get_summary(current_user: dict = Depends(get_current_user)):
    """Get quarantine summary stats"""
    return await get_quarantine_summary()

@router.get("/{entry_id}")
async def get_entry(entry_id: str, current_user: dict = Depends(get_current_user)):
    """Get specific quarantine entry"""
    entry = await get_quarantine_entry(entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    return entry

@router.post("/{entry_id}/restore")
async def restore_entry(entry_id: str, current_user: dict = Depends(get_current_user)):
    """Restore a quarantined file"""
    result = await restore_file(entry_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Restore failed"))
    return result

@router.delete("/{entry_id}")
async def delete_entry(entry_id: str, current_user: dict = Depends(get_current_user)):
    """Permanently delete a quarantined file"""
    result = await delete_quarantined(entry_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Delete failed"))
    return result
