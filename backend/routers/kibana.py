"""
Kibana Dashboard Router - Pre-built security dashboards
"""
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import PlainTextResponse
from typing import Optional
from pydantic import BaseModel

from .dependencies import get_current_user, check_permission
from kibana_dashboards import kibana_dashboard_service, KibanaDashboardService

router = APIRouter(prefix="/kibana", tags=["Kibana Dashboards"])


class ConfigureKibanaRequest(BaseModel):
    elasticsearch_url: str
    api_key: str
    kibana_url: Optional[str] = None


@router.get("/dashboards")
async def get_available_dashboards(current_user: dict = Depends(get_current_user)):
    """Get list of available pre-built Kibana dashboards"""
    dashboards = kibana_dashboard_service.get_available_dashboards()
    return {"dashboards": dashboards, "count": len(dashboards)}


@router.get("/dashboards/{dashboard_id}")
async def get_dashboard_config(
    dashboard_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get full configuration for a specific dashboard"""
    config = kibana_dashboard_service.get_dashboard_config(dashboard_id)
    if not config:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return config


@router.get("/dashboards/{dashboard_id}/export")
async def export_dashboard(
    dashboard_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Export dashboard in NDJSON format for Kibana import"""
    export = kibana_dashboard_service.get_dashboard_export(dashboard_id)
    if not export:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return PlainTextResponse(
        content=export,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f"attachment; filename={dashboard_id}.ndjson"}
    )


@router.get("/dashboards/{dashboard_id}/queries")
async def get_dashboard_queries(
    dashboard_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get Elasticsearch queries for dashboard visualizations"""
    queries = kibana_dashboard_service.get_visualization_queries(dashboard_id)
    if not queries:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return {"dashboard_id": dashboard_id, "queries": queries}


@router.get("/export-all")
async def export_all_dashboards(current_user: dict = Depends(get_current_user)):
    """Export all dashboards in NDJSON format"""
    export = kibana_dashboard_service.get_all_dashboards_export()
    return PlainTextResponse(
        content=export,
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=all-security-dashboards.ndjson"}
    )


@router.post("/configure")
async def configure_kibana(
    request: ConfigureKibanaRequest,
    current_user: dict = Depends(check_permission("manage_users"))
):
    """Configure Kibana connection settings"""
    kibana_dashboard_service.configure(
        elasticsearch_url=request.elasticsearch_url,
        api_key=request.api_key,
        kibana_url=request.kibana_url
    )
    return {"message": "Kibana configured successfully"}


@router.post("/setup-index")
async def setup_index_pattern(
    current_user: dict = Depends(check_permission("manage_users"))
):
    """Create security-events index pattern in Kibana"""
    result = await kibana_dashboard_service.create_index_pattern()
    return result


@router.get("/status")
async def get_kibana_status(current_user: dict = Depends(get_current_user)):
    """Get Kibana integration status"""
    return {
        "configured": bool(kibana_dashboard_service.elasticsearch_url),
        "elasticsearch_url": kibana_dashboard_service.elasticsearch_url or "Not configured",
        "kibana_url": kibana_dashboard_service.kibana_url or "Not configured",
        "dashboards_available": len(kibana_dashboard_service.dashboards)
    }
