from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from services.world_model import WorldModelService
except Exception:
    from backend.services.world_model import WorldModelService

try:
    from triune.loki import LokiService
    from triune.metatron import MetatronService
    from triune.michael import MichaelService
except Exception:
    from backend.triune.loki import LokiService
    from backend.triune.metatron import MetatronService
    from backend.triune.michael import MichaelService


class TriuneOrchestrator:
    """Central orchestration point for Triune reasoning over world-state changes.

    Flow:
      world-state snapshot -> Metatron assess -> Michael plan -> Loki challenge
    """

    def __init__(self, db: Any):
        self.db = db
        self.world_model = WorldModelService(db)
        self.metatron = MetatronService(db)
        self.michael = MichaelService(db)
        self.loki = LokiService(db)

    async def handle_world_change(
        self,
        event_type: str,
        entity_ids: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        entity_ids = entity_ids or []
        context = context or {}

        world_snapshot = await self._build_world_snapshot(entity_ids)
        metatron_assessment = await self.metatron.assess_world_state(
            snapshot=world_snapshot,
            event_type=event_type,
            context=context,
        )

        candidates = await self._resolve_candidates(entity_ids)
        michael_plan = await self.michael.plan_actions(
            candidates=candidates,
            world_snapshot=world_snapshot,
            policy_tier=metatron_assessment.get("approval_tier_suggestion", "standard"),
            context=context,
        )

        loki_advisory = await self.loki.challenge_plan(
            world_snapshot=world_snapshot,
            michael_plan=michael_plan,
            event_type=event_type,
            context=context,
        )

        return {
            "event_type": event_type,
            "entity_ids": entity_ids,
            "context": context,
            "world_snapshot": world_snapshot,
            "metatron": metatron_assessment,
            "michael": {
                "candidates": candidates,
                "ranked": michael_plan.get("ranked_action_candidates", []),
                "plan": michael_plan,
            },
            "loki": loki_advisory,
        }

    async def _build_world_snapshot(self, entity_ids: List[str]) -> Dict[str, Any]:
        entities = []
        for entity_id in entity_ids:
            doc = await self.world_model.entities.find_one({"id": entity_id}, {"_id": 0})
            if doc:
                entities.append(doc)

        hotspots = []
        for hotspot in await self.world_model.list_hotspots(limit=5):
            if hasattr(hotspot, "model_dump"):
                hotspots.append(hotspot.model_dump())
            else:
                hotspots.append(hotspot.dict())

        attack_path_graph = await self.world_model.compute_attack_path(seed_ids=entity_ids or None, max_depth=3)
        graph_metrics = await self.world_model.compute_graph_metrics(seed_ids=entity_ids or None, max_depth=3)

        edges: List[Dict[str, Any]] = []
        try:
            edges = await self.world_model.edges.find({}, {"_id": 0}).sort("created", -1).to_list(100)
        except Exception:
            edges = attack_path_graph.get("edges", [])[:100]

        campaigns: List[Dict[str, Any]] = []
        try:
            campaigns = await self.world_model.campaigns.find({}, {"_id": 0}).sort("first_detected", -1).to_list(20)
        except Exception:
            campaigns = []

        recent_world_events: List[Dict[str, Any]] = []
        try:
            recent_world_events = await self.db.world_events.find({}, {"_id": 0}).sort("created", -1).to_list(100)
        except Exception:
            recent_world_events = []

        active_responses: List[Dict[str, Any]] = []
        try:
            active_responses = await self.db.response_history.find({"status": {"$in": ["pending", "in_progress", "active"]}}, {"_id": 0}).sort("timestamp", -1).to_list(50)
        except Exception:
            active_responses = []

        trust_state: Dict[str, Any] = {}
        try:
            for ent in entities:
                attrs = ent.get("attributes", {})
                if attrs.get("trust_state"):
                    trust_state[ent.get("id")] = attrs.get("trust_state")
            if not trust_state:
                identities = await self.db.world_entities.find({"attributes.trust_state": {"$exists": True}}, {"_id": 0, "id": 1, "attributes.trust_state": 1}).to_list(200)
                for ident in identities:
                    trust_state[ident.get("id")] = (ident.get("attributes") or {}).get("trust_state")
        except Exception:
            trust_state = {}

        sector_risk: Dict[str, Any] = {}
        try:
            pipeline = [
                {"$match": {"attributes.risk_score": {"$exists": True}}},
                {"$project": {"sector": {"$ifNull": ["$attributes.sector", "unknown"]}, "risk": "$attributes.risk_score"}},
                {"$group": {"_id": "$sector", "avg_risk": {"$avg": "$risk"}, "entities": {"$sum": 1}}},
                {"$sort": {"avg_risk": -1}},
            ]
            sector_rows = await self.db.world_entities.aggregate(pipeline).to_list(20)
            sector_risk = {row.get("_id", "unknown"): {"avg_risk": row.get("avg_risk", 0.0), "entities": row.get("entities", 0)} for row in sector_rows}
        except Exception:
            sector_risk = {}

        attack_path_summary = {
            "node_count": len(attack_path_graph.get("nodes", [])),
            "edge_count": len(attack_path_graph.get("edges", [])),
            "top_nodes": [n.get("id") for n in attack_path_graph.get("nodes", [])[:10]],
            "graph_metrics": graph_metrics,
        }

        return {
            "entities": entities,
            "hotspots": hotspots,
            "edges": edges,
            "campaigns": campaigns,
            "trust_state": trust_state,
            "recent_world_events": recent_world_events,
            "active_responses": active_responses,
            "sector_risk": sector_risk,
            "attack_path_graph": attack_path_graph,
            "attack_path_summary": attack_path_summary,
            "entity_count": await self.world_model.count_entities(),
        }

    async def _resolve_candidates(self, entity_ids: List[str]) -> List[str]:
        if entity_ids:
            return [f"investigate:{entity_id}" for entity_id in entity_ids]

        actions = await self.world_model.list_actions(limit=10)
        return [f"{action['action']}:{action['entity_id']}" for action in actions]
