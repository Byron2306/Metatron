"""
Attack Path Analysis API Router
================================
REST API endpoints for crown jewel asset protection, blast radius analysis,
and attack path visualization.

Endpoints:
- POST /assets - Register a crown jewel asset
- GET /assets - List crown jewel assets
- GET /assets/{asset_id} - Get asset details
- DELETE /assets/{asset_id} - Remove asset
- GET /assets/{asset_id}/blast-radius - Get blast radius
- GET /assets/{asset_id}/attack-paths - Get attack paths to asset
- POST /analysis/full - Run full attack path analysis
- GET /graph - Get attack graph visualization

Author: Seraph Security Team
Version: 1.0.0
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
import asyncio
import logging

from attack_path_analysis import (
    get_attack_path_analyzer,
    AttackPathAnalyzer,
    CrownJewelAsset,
    AssetType,
    CriticalityLevel,
    AttackPath,
    BlastRadiusResult,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/attack-paths", tags=["Attack Path Analysis"])


# =============================================================================
# PYDANTIC MODELS
# =============================================================================

class AssetCreateRequest(BaseModel):
    """Request to register a crown jewel asset"""
    name: str = Field(..., description="Asset name")
    asset_type: str = Field(..., description="Asset type: server, database, application, network_device, identity_store, secrets_vault, endpoint, container, cloud_resource")
    identifier: str = Field(..., description="Unique identifier (IP, hostname, ARN, etc.)")
    criticality: str = Field(default="high", description="Criticality: low, medium, high, critical, crown_jewel")
    description: Optional[str] = Field(None, description="Asset description")
    owner: Optional[str] = Field(None, description="Asset owner/team")
    data_classification: Optional[str] = Field(None, description="Data sensitivity level")
    compliance_scope: Optional[List[str]] = Field(None, description="Compliance frameworks")
    tags: Optional[Dict[str, str]] = Field(None, description="Custom tags")
    dependencies: Optional[List[str]] = Field(None, description="List of dependent asset IDs")
    network_zone: Optional[str] = Field(None, description="Network zone (dmz, internal, cloud, etc.)")


class AssetResponse(BaseModel):
    """Crown jewel asset response"""
    asset_id: str
    name: str
    asset_type: str
    identifier: str
    criticality: str
    criticality_score: int
    description: Optional[str]
    owner: Optional[str]
    data_classification: Optional[str]
    compliance_scope: List[str]
    tags: Dict[str, str]
    dependencies: List[str]
    network_zone: str
    created_at: str
    updated_at: str


class AssetListResponse(BaseModel):
    """List of assets response"""
    total: int
    assets: List[AssetResponse]


class AttackPathResponse(BaseModel):
    """Attack path response"""
    path_id: str
    source: str
    target: str
    path_length: int
    risk_score: int
    mitre_techniques: List[str]
    steps: List[Dict[str, Any]]
    mitigations: List[str]


class BlastRadiusResponse(BaseModel):
    """Blast radius analysis response"""
    asset_id: str
    asset_name: str
    total_affected: int
    affected_by_criticality: Dict[str, int]
    affected_assets: List[Dict[str, Any]]
    risk_summary: Dict[str, Any]
    recommendations: List[str]


class FullAnalysisRequest(BaseModel):
    """Request for full attack path analysis"""
    include_external_threats: bool = Field(default=True)
    max_path_length: int = Field(default=10, ge=1, le=20)
    min_risk_score: int = Field(default=0, ge=0, le=100)


class FullAnalysisResponse(BaseModel):
    """Full analysis result"""
    analysis_id: str
    timestamp: str
    total_assets: int
    total_paths: int
    high_risk_paths: int
    critical_findings: List[Dict[str, Any]]
    risk_heatmap: Dict[str, int]
    recommendations: List[str]


class GraphResponse(BaseModel):
    """Attack graph visualization data"""
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    clusters: List[Dict[str, Any]]


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.post("/assets", response_model=AssetResponse, status_code=201)
async def register_asset(request: AssetCreateRequest):
    """
    Register a crown jewel asset for attack path monitoring.
    
    Crown jewels are critical assets that require enhanced protection.
    Registering them enables:
    - Blast radius analysis
    - Attack path discovery
    - Priority alerting
    - Compliance tracking
    """
    try:
        asset_type = AssetType(request.asset_type)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid asset type: {request.asset_type}. "
                   f"Valid types: {[t.value for t in AssetType]}"
        )
    
    try:
        criticality = CriticalityLevel(request.criticality)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid criticality: {request.criticality}. "
                   f"Valid levels: {[c.value for c in CriticalityLevel]}"
        )
    
    analyzer = get_attack_path_analyzer()
    
    asset = CrownJewelAsset(
        name=request.name,
        asset_type=asset_type,
        identifier=request.identifier,
        criticality=criticality,
        description=request.description or "",
        owner=request.owner or "",
        data_classification=request.data_classification or "confidential",
        compliance_scope=request.compliance_scope or [],
        tags=request.tags or {},
        dependencies=request.dependencies or [],
        network_zone=request.network_zone or "internal",
    )
    
    analyzer.register_crown_jewel(asset)
    
    return AssetResponse(
        asset_id=asset.asset_id,
        name=asset.name,
        asset_type=asset.asset_type.value,
        identifier=asset.identifier,
        criticality=asset.criticality.value,
        criticality_score=asset.criticality_score,
        description=asset.description,
        owner=asset.owner,
        data_classification=asset.data_classification,
        compliance_scope=asset.compliance_scope,
        tags=asset.tags,
        dependencies=asset.dependencies,
        network_zone=asset.network_zone,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
    )


@router.get("/assets", response_model=AssetListResponse)
async def list_assets(
    asset_type: Optional[str] = Query(None, description="Filter by asset type"),
    criticality: Optional[str] = Query(None, description="Filter by criticality"),
    network_zone: Optional[str] = Query(None, description="Filter by network zone"),
    tag_key: Optional[str] = Query(None, description="Filter by tag key"),
    tag_value: Optional[str] = Query(None, description="Filter by tag value"),
):
    """
    List registered crown jewel assets.
    
    Supports filtering by various criteria.
    """
    analyzer = get_attack_path_analyzer()
    assets = list(analyzer.crown_jewels.values())
    
    # Apply filters
    if asset_type:
        assets = [a for a in assets if a.asset_type.value == asset_type]
    
    if criticality:
        assets = [a for a in assets if a.criticality.value == criticality]
    
    if network_zone:
        assets = [a for a in assets if a.network_zone == network_zone]
    
    if tag_key and tag_value:
        assets = [a for a in assets if a.tags.get(tag_key) == tag_value]
    elif tag_key:
        assets = [a for a in assets if tag_key in a.tags]
    
    return AssetListResponse(
        total=len(assets),
        assets=[
            AssetResponse(
                asset_id=a.asset_id,
                name=a.name,
                asset_type=a.asset_type.value,
                identifier=a.identifier,
                criticality=a.criticality.value,
                criticality_score=a.criticality_score,
                description=a.description,
                owner=a.owner,
                data_classification=a.data_classification,
                compliance_scope=a.compliance_scope,
                tags=a.tags,
                dependencies=a.dependencies,
                network_zone=a.network_zone,
                created_at=a.created_at,
                updated_at=a.updated_at,
            )
            for a in assets
        ]
    )


@router.get("/assets/{asset_id}", response_model=AssetResponse)
async def get_asset(asset_id: str):
    """Get details of a specific crown jewel asset."""
    analyzer = get_attack_path_analyzer()
    
    asset = analyzer.crown_jewels.get(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset not found: {asset_id}")
    
    return AssetResponse(
        asset_id=asset.asset_id,
        name=asset.name,
        asset_type=asset.asset_type.value,
        identifier=asset.identifier,
        criticality=asset.criticality.value,
        criticality_score=asset.criticality_score,
        description=asset.description,
        owner=asset.owner,
        data_classification=asset.data_classification,
        compliance_scope=asset.compliance_scope,
        tags=asset.tags,
        dependencies=asset.dependencies,
        network_zone=asset.network_zone,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
    )


@router.delete("/assets/{asset_id}")
async def delete_asset(asset_id: str):
    """Remove a crown jewel asset from monitoring."""
    analyzer = get_attack_path_analyzer()
    
    if asset_id not in analyzer.crown_jewels:
        raise HTTPException(status_code=404, detail=f"Asset not found: {asset_id}")
    
    del analyzer.crown_jewels[asset_id]
    
    return {"message": f"Asset {asset_id} removed", "timestamp": datetime.now(timezone.utc).isoformat()}


@router.get("/assets/{asset_id}/blast-radius", response_model=BlastRadiusResponse)
async def get_blast_radius(
    asset_id: str,
    depth: int = Query(3, ge=1, le=10, description="Analysis depth"),
):
    """
    Calculate blast radius if an asset is compromised.
    
    Returns all assets that could be affected by the compromise,
    categorized by criticality and impact level.
    """
    analyzer = get_attack_path_analyzer()
    
    if asset_id not in analyzer.crown_jewels:
        raise HTTPException(status_code=404, detail=f"Asset not found: {asset_id}")
    
    result = await analyzer.calculate_blast_radius(asset_id, max_depth=depth)
    
    return BlastRadiusResponse(
        asset_id=result.source_asset,
        asset_name=analyzer.crown_jewels[asset_id].name,
        total_affected=result.total_affected,
        affected_by_criticality={
            k.value if hasattr(k, 'value') else str(k): v 
            for k, v in result.affected_by_criticality.items()
        },
        affected_assets=[
            {
                "asset_id": a.asset_id,
                "name": a.name,
                "criticality": a.criticality.value,
                "impact_level": result.impact_by_asset.get(a.asset_id, "unknown"),
            }
            for a in result.affected_assets
        ],
        risk_summary={
            "blast_radius_score": result.blast_radius_score,
            "max_criticality_affected": result.max_criticality_affected.value if result.max_criticality_affected else "none",
        },
        recommendations=result.recommendations,
    )


@router.get("/assets/{asset_id}/attack-paths")
async def get_attack_paths(
    asset_id: str,
    max_paths: int = Query(10, ge=1, le=50),
    min_risk: int = Query(0, ge=0, le=100),
):
    """
    Discover attack paths leading to a crown jewel asset.
    
    Identifies potential attack chains from external or internal
    threat sources to the target asset.
    """
    analyzer = get_attack_path_analyzer()
    
    if asset_id not in analyzer.crown_jewels:
        raise HTTPException(status_code=404, detail=f"Asset not found: {asset_id}")
    
    paths = await analyzer.find_attack_paths(
        target_asset_id=asset_id,
        max_paths=max_paths,
        min_risk_score=min_risk,
    )
    
    return {
        "target_asset": asset_id,
        "total_paths": len(paths),
        "paths": [
            AttackPathResponse(
                path_id=p.path_id,
                source=p.source_asset,
                target=p.target_asset,
                path_length=len(p.steps),
                risk_score=p.risk_score,
                mitre_techniques=p.mitre_techniques,
                steps=[
                    {
                        "step": i + 1,
                        "from_asset": step.get("from"),
                        "to_asset": step.get("to"),
                        "technique": step.get("technique"),
                        "description": step.get("description"),
                    }
                    for i, step in enumerate(p.steps)
                ],
                mitigations=p.mitigations,
            )
            for p in paths
        ]
    }


@router.post("/analysis/full", response_model=FullAnalysisResponse)
async def run_full_analysis(
    request: FullAnalysisRequest,
    background_tasks: BackgroundTasks,
):
    """
    Run comprehensive attack path analysis across all assets.
    
    Analyzes all crown jewel assets to identify:
    - All attack paths
    - High-risk paths requiring immediate attention
    - Common vulnerabilities across paths
    - Risk heatmap by asset and zone
    """
    analyzer = get_attack_path_analyzer()
    
    if not analyzer.crown_jewels:
        raise HTTPException(
            status_code=400, 
            detail="No crown jewel assets registered. Register assets first."
        )
    
    analysis_id = f"analysis-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    
    # Run analysis
    all_paths = []
    for asset_id in analyzer.crown_jewels:
        paths = await analyzer.find_attack_paths(
            target_asset_id=asset_id,
            max_paths=20,
            min_risk_score=request.min_risk_score,
        )
        all_paths.extend(paths)
    
    # Calculate risk heatmap
    risk_heatmap = {}
    for path in all_paths:
        for step in path.steps:
            asset = step.get("to", step.get("from"))
            if asset:
                risk_heatmap[asset] = risk_heatmap.get(asset, 0) + path.risk_score // len(path.steps)
    
    # Identify critical findings
    high_risk_paths = [p for p in all_paths if p.risk_score >= 70]
    critical_findings = [
        {
            "path_id": p.path_id,
            "risk_score": p.risk_score,
            "target": p.target_asset,
            "techniques": p.mitre_techniques[:3],
            "recommendation": p.mitigations[0] if p.mitigations else "Review path manually",
        }
        for p in sorted(high_risk_paths, key=lambda x: x.risk_score, reverse=True)[:10]
    ]
    
    # Generate recommendations
    recommendations = []
    if high_risk_paths:
        recommendations.append(f"Address {len(high_risk_paths)} high-risk attack paths immediately")
    
    # Common techniques across paths
    technique_counts: Dict[str, int] = {}
    for path in all_paths:
        for tech in path.mitre_techniques:
            technique_counts[tech] = technique_counts.get(tech, 0) + 1
    
    top_techniques = sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    for tech, count in top_techniques:
        recommendations.append(f"Implement controls for {tech} (appears in {count} paths)")
    
    return FullAnalysisResponse(
        analysis_id=analysis_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        total_assets=len(analyzer.crown_jewels),
        total_paths=len(all_paths),
        high_risk_paths=len(high_risk_paths),
        critical_findings=critical_findings,
        risk_heatmap=risk_heatmap,
        recommendations=recommendations,
    )


@router.get("/graph", response_model=GraphResponse)
async def get_attack_graph(
    include_paths: bool = Query(True, description="Include attack paths in graph"),
    min_criticality: str = Query("medium", description="Minimum asset criticality to include"),
):
    """
    Get attack graph data for visualization.
    
    Returns nodes (assets) and edges (relationships/paths)
    suitable for graph visualization libraries.
    """
    analyzer = get_attack_path_analyzer()
    
    # Build nodes
    nodes = []
    for asset_id, asset in analyzer.crown_jewels.items():
        nodes.append({
            "id": asset_id,
            "label": asset.name,
            "type": asset.asset_type.value,
            "criticality": asset.criticality.value,
            "criticality_score": asset.criticality_score,
            "network_zone": asset.network_zone,
            "size": 10 + asset.criticality_score // 10,  # Size based on criticality
        })
    
    # Build edges from dependencies
    edges = []
    edge_id = 0
    for asset_id, asset in analyzer.crown_jewels.items():
        for dep_id in asset.dependencies:
            if dep_id in analyzer.crown_jewels:
                edges.append({
                    "id": f"edge-{edge_id}",
                    "source": dep_id,
                    "target": asset_id,
                    "type": "dependency",
                    "label": "depends_on",
                })
                edge_id += 1
    
    # Include attack paths as edges
    if include_paths:
        for path in analyzer.attack_paths.values():
            for i, step in enumerate(path.steps[:-1]):
                from_asset = step.get("from") or step.get("to")
                to_asset = path.steps[i + 1].get("to") or path.steps[i + 1].get("from")
                if from_asset and to_asset:
                    edges.append({
                        "id": f"path-{path.path_id}-{i}",
                        "source": from_asset,
                        "target": to_asset,
                        "type": "attack_path",
                        "risk_score": path.risk_score,
                        "technique": step.get("technique", "unknown"),
                    })
    
    # Group by network zone
    clusters = []
    zones = set(a.network_zone for a in analyzer.crown_jewels.values())
    for zone in zones:
        zone_assets = [a.asset_id for a in analyzer.crown_jewels.values() if a.network_zone == zone]
        clusters.append({
            "id": f"zone-{zone}",
            "label": zone.upper(),
            "members": zone_assets,
        })
    
    return GraphResponse(
        nodes=nodes,
        edges=edges,
        clusters=clusters,
    )


@router.get("/health")
async def health_check():
    """Health check for attack path analysis service."""
    analyzer = get_attack_path_analyzer()
    
    return {
        "status": "healthy",
        "total_assets": len(analyzer.crown_jewels),
        "total_paths": len(analyzer.attack_paths),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
