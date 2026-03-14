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
        return {
            "entities": entities,
            "hotspots": hotspots,
            "entity_count": await self.world_model.count_entities(),
        }

    async def _resolve_candidates(self, entity_ids: List[str]) -> List[str]:
        if entity_ids:
            return [f"investigate:{entity_id}" for entity_id in entity_ids]

        actions = await self.world_model.list_actions(limit=10)
        return [f"{action['action']}:{action['entity_id']}" for action in actions]
