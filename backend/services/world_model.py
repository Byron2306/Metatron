from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime
from typing import Any, Dict, List, Optional
from collections import deque


class EntityType(str, Enum):
    host = "host"
    user = "user"
    agent = "agent"
    process = "process"
    session = "session"
    token = "token"
    file = "file"
    alert = "alert"
    detection = "detection"
    campaign = "campaign"


class WorldEntity(BaseModel):
    id: str
    type: EntityType
    attributes: Dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class WorldEdge(BaseModel):
    source: str
    target: str
    relation: str
    created: datetime = Field(default_factory=datetime.utcnow)


class Campaign(BaseModel):
    id: str
    name: Optional[str] = None
    techniques: List[str] = Field(default_factory=list)
    confidence: float = 0.0
    entities: List[str] = Field(default_factory=list)
    # New structured campaign fields to canonicalize narrative
    objective: Optional[str] = None
    stage: Optional[str] = None
    predicted_next_moves: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    # Generic attributes bag for backward compatibility
    attributes: Dict[str, Any] = Field(default_factory=dict)
    first_detected: datetime = Field(default_factory=datetime.utcnow)


class WorldModelService:
    """Simple service for managing the canonical world model."""

    def __init__(self, db: Any = None):
        self.db = db
        # Phase 1 placeholder fields for upcoming harmonic governance dimensions.
        self.current_genre_mode: Optional[str] = None
        self.current_score_id: Optional[str] = None
        self.current_governance_epoch: Optional[str] = None
        if db is not None:
            self.entities = db.world_entities
            self.edges = db.world_edges
            self.campaigns = db.campaigns

    def set_database(self, db: Any):
        self.__init__(db)

    def get_governance_placeholders(self) -> Dict[str, Optional[str]]:
        return {
            "current_genre_mode": self.current_genre_mode,
            "current_score_id": self.current_score_id,
            "current_governance_epoch": self.current_governance_epoch,
        }

    def set_governance_placeholders(
        self,
        *,
        current_genre_mode: Optional[str] = None,
        current_score_id: Optional[str] = None,
        current_governance_epoch: Optional[str] = None,
    ) -> Dict[str, Optional[str]]:
        self.current_genre_mode = current_genre_mode
        self.current_score_id = current_score_id
        self.current_governance_epoch = current_governance_epoch
        return self.get_governance_placeholders()

    async def upsert_entity(self, entity: WorldEntity):
        # insert or update entity record
        await self.entities.update_one(
            {"id": entity.id, "type": entity.type},
            {"$set": entity.dict()},
            upsert=True,
        )
        # recalc risk score after ingest
        await self.calculate_risk(entity.id)

    async def calculate_risk(self, entity_id: str) -> float:
        """Recompute and persist a simple risk score for an entity."""
        doc = await self.entities.find_one({"id": entity_id})
        if not doc:
            return 0.0
        attrs = doc.get("attributes", {})
        # detection influence
        dets = attrs.get("detections") or []
        det_count = len(dets)
        avg_conf = (
            sum(d.get("confidence", 50) for d in dets) / det_count if det_count else 0
        )
        # severity influence (if detections carry severity keys)
        avg_sev = 0
        if det_count:
            avg_sev = sum(d.get("severity", 2) for d in dets) / det_count
        # technique influence
        techs = attrs.get("techniques") or []
        tech_count = len(techs)
        # edge centrality: number of connected edges
        edge_count = 0
        try:
            edge_count = await self.edges.count_documents({"$or": [{"source": entity_id}, {"target": entity_id}]})
        except Exception:
            edge_count = 0
        centrality = min(1.0, edge_count / 20.0)
        # frequency: detections per day since first_seen
        freq = 0.0
        if det_count and doc.get("first_seen"):
            try:
                days = (datetime.now() - doc.get("first_seen")).days or 1
                freq = det_count / days
            except Exception:
                freq = det_count
        # policy violations and token anomalies
        pv = 1.0 if attrs.get("policy_violation") else 0.0
        te_count = len(attrs.get("token_events", [])) if attrs.get("token_events") else 0
        # simple weighted formula
        risk = min(
            1.0,
            0.1 * det_count
            + 0.0005 * avg_conf
            + 0.05 * tech_count
            + 0.02 * avg_sev
            + 0.2 * centrality
            + 0.05 * freq
            + 0.2 * pv
            + 0.05 * te_count,
        )
        await self.entities.update_one({"id": entity_id}, {"$set": {"attributes.risk_score": risk}})
        return risk

    async def add_edge(self, edge: WorldEdge):
        await self.edges.insert_one(edge.dict())
        # Recalculate risk for connected entities — best-effort, don't fail the insert
        try:
            await self.calculate_risk(edge.source)
        except Exception:
            pass
        try:
            await self.calculate_risk(edge.target)
        except Exception:
            pass

    async def create_campaign(self, camp: Campaign):
        await self.campaigns.insert_one(camp.dict())

    async def count_entities(self, query=None) -> int:
        query = query or {}
        return await self.entities.count_documents(query)

    async def get_latest_campaign(self) -> Optional[Campaign]:
        doc = await self.campaigns.find_one({}, sort=[("first_detected", -1)])
        return Campaign(**doc) if doc else None

    async def list_hotspots(self, limit: int = 10) -> List[WorldEntity]:
        # naive hotspots: entities with highest risk_score attribute
        cursor = self.entities.find({"attributes.risk_score": {"$exists": True}}, sort=[("attributes.risk_score", -1)], limit=limit)
        return [WorldEntity(**e) async for e in cursor]

    async def list_timeline(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent timeline events (detections, alerts, campaigns) sorted by last_seen or first_detected."""
        # prioritize detection/alert/campaign entities
        types = [EntityType.detection.value, EntityType.alert.value, EntityType.campaign.value]
        cursor = self.entities.find({"type": {"$in": types}}, sort=[("last_seen", -1)], limit=limit)
        out = []
        async for d in cursor:
            e = WorldEntity(**d)
            rec = {
                "id": e.id,
                "type": e.type,
                "attributes": e.attributes,
                "first_seen": e.first_seen,
                "last_seen": e.last_seen,
            }
            out.append(rec)
        return out

    async def compute_attack_path(self, seed_ids: Optional[List[str]] = None, max_depth: int = 3) -> Dict[str, Any]:
        """Build a simple attack-path graph starting from seed entities by traversing edges up to max_depth."""
        # choose seeds: provided or top hotspots
        if not seed_ids:
            seeds = [e.id for e in await self.list_hotspots(limit=3)]
            if not seeds and hasattr(self, "entities") and self.entities is not None:
                # Fallback for fresh deployments where risk scores are absent:
                # start from the most recently observed entities so the graph remains informative.
                cursor = self.entities.find({}, {"_id": 0, "id": 1}, sort=[("last_seen", -1)], limit=8)
                seeds = [doc.get("id") async for doc in cursor if doc.get("id")]
        else:
            seeds = seed_ids
        nodes = {}
        edges_out = []
        visited = set(seeds)
        frontier = deque([(s, 0) for s in seeds])
        # add seed node docs
        for s in seeds:
            doc = await self.entities.find_one({"id": s}, {"_id": 0})
            if doc:
                nodes[s] = {"id": s, "type": doc.get("type"), "attributes": doc.get("attributes", {})}
        while frontier:
            current, depth = frontier.popleft()
            if depth >= max_depth:
                continue
            # find outgoing and incoming edges
            cursor = self.edges.find({"$or": [{"source": current}, {"target": current}]})
            async for ed in cursor:
                src = ed.get("source")
                tgt = ed.get("target")
                rel = ed.get("relation")
                edges_out.append({"source": src, "target": tgt, "relation": rel, "created": ed.get("created")})
                for nid in (src, tgt):
                    if nid not in nodes:
                        doc = await self.entities.find_one({"id": nid}, {"_id": 0})
                        nodes[nid] = {"id": nid, "type": doc.get("type") if doc else None, "attributes": doc.get("attributes", {}) if doc else {}}
                    if nid not in visited:
                        visited.add(nid)
                        frontier.append((nid, depth + 1))
        return {"nodes": list(nodes.values()), "edges": edges_out}

    async def compute_graph_metrics(self, seed_ids: Optional[List[str]] = None, max_depth: int = 3) -> Dict[str, Any]:
        """Compute simple graph metrics useful for reasoning and UI.

        Returns:
          - centrality: dict of entity_id -> centrality score (0..1)
          - avg_path_distance: average shortest-path distance from seeds
          - privilege_escalation_likelihood: heuristic score 0..1
          - blast_radius: largest connected component size
        """
        # build nodes and adjacency
        try:
            nodes = set()
            adj = {}
            cursor = self.edges.find({}) if hasattr(self, "edges") and self.edges is not None else []
            async for ed in cursor:
                src = ed.get("source")
                tgt = ed.get("target")
                nodes.add(src)
                nodes.add(tgt)
                adj.setdefault(src, set()).add(tgt)
                adj.setdefault(tgt, set()).add(src)

            # centrality: degree normalized by max degree
            degrees = {n: len(adj.get(n, [])) for n in nodes}
            maxd = max(degrees.values()) if degrees else 1
            centrality = {n: (degrees.get(n, 0) / maxd) for n in nodes}

            # average shortest path distance from seeds using BFS
            from collections import deque
            seeds = seed_ids or (list(nodes)[:3] if nodes else [])
            total_dist = 0
            count = 0
            for s in seeds:
                visited = {s}
                q = deque([(s, 0)])
                while q:
                    cur, d = q.popleft()
                    total_dist += d
                    count += 1
                    for nb in adj.get(cur, []):
                        if nb not in visited:
                            visited.add(nb)
                            q.append((nb, d + 1))
            avg_path_distance = (total_dist / count) if count else 0.0

            # privilege escalation likelihood: heuristic based on technique tags in entities
            pel = 0.0
            try:
                cursor = self.entities.find({}) if hasattr(self, "entities") and self.entities is not None else []
                tech_count = 0
                suspect = 0
                async for e in cursor:
                    attrs = e.get("attributes", {}) or {}
                    techs = attrs.get("techniques") or []
                    if any(t.startswith("T15") or t.startswith("T10") for t in techs):
                        suspect += 1
                    tech_count += 1
                if tech_count:
                    pel = min(1.0, suspect / max(1.0, tech_count))
            except Exception:
                pel = 0.0

            # blast radius: find largest connected component
            visited = set()
            largest = 0
            for n in nodes:
                if n in visited:
                    continue
                size = 0
                stack = [n]
                visited.add(n)
                while stack:
                    cur = stack.pop()
                    size += 1
                    for nb in adj.get(cur, []):
                        if nb not in visited:
                            visited.add(nb)
                            stack.append(nb)
                largest = max(largest, size)

            return {
                "centrality": centrality,
                "avg_path_distance": avg_path_distance,
                "privilege_escalation_likelihood": pel,
                "blast_radius": largest,
            }
        except Exception:
            return {"centrality": {}, "avg_path_distance": 0.0, "privilege_escalation_likelihood": 0.0, "blast_radius": 0}

    async def list_actions(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Suggest simple remediation actions based on hotspots.

        These are lightweight heuristics for the UI; ML-driven recommendations belong to Michael.
        """
        actions = []
        hotspots = await self.list_hotspots(limit=limit)
        for h in hotspots:
            r = h.attributes.get("risk_score", 0)
            if h.type == EntityType.host:
                if r >= 0.8:
                    actions.append({"entity_id": h.id, "action": "isolate_host", "reason": "high_risk"})
                else:
                    actions.append({"entity_id": h.id, "action": "monitor_host", "reason": "elevated_risk"})
            elif h.type == EntityType.user:
                if r >= 0.7:
                    actions.append({"entity_id": h.id, "action": "force_password_reset", "reason": "user_high_risk"})
                else:
                    actions.append({"entity_id": h.id, "action": "require_2fa", "reason": "user_elevated_risk"})
            else:
                actions.append({"entity_id": h.id, "action": "investigate", "reason": "general"})
        return actions

    async def compute_trust_metrics(self) -> Dict[str, Any]:
        # simple trust drift computed from policy violation count
        violations = await self.entities.count_documents({"attributes.policy_violation": True})
        identity_drift = "stable" if violations < 5 else "degrading"
        device_drift = "stable" if violations < 10 else "degrading"
        return {
            "identity": identity_drift,
            "device": device_drift,
            "agent_health": "unknown",
            "policy_violations": violations,
            "token_anomalies": 0,
        }

    # more methods will be added as the architecture expands
