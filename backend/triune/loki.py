from fastapi import APIRouter
from typing import Any
from datetime import datetime, timezone

router = APIRouter()

class LokiService:
    def __init__(self, db: Any = None):
        self.db = db

    def set_database(self, db: Any):
        self.__init__(db)

    async def generate_hunts(self, count: int = 3) -> list:
        # Return simple placeholder hunt hypotheses
        return [f"hunt_{i}" for i in range(count)]

    async def challenge_plan(
        self,
        world_snapshot: dict,
        michael_plan: dict,
        event_type: str,
        context: dict | None = None,
    ) -> dict:
        """Generate dissenting/advisory hypotheses from same world-state context."""
        context = context or {}
        ranked = michael_plan.get("ranked_action_candidates") or michael_plan.get("ranked") or []
        top = ranked[0]["candidate"] if ranked else "investigate"

        alternatives = [
            {"hypothesis": "attacker_objective_is_disruption", "confidence": 0.52},
            {"hypothesis": "attacker_objective_is_credential_access", "confidence": 0.63},
            {"hypothesis": "attacker_objective_is_data_staging", "confidence": 0.41},
        ]

        hunt_suggestions = [
            f"hunt:children_of_{top.split(':', 1)[0]}",
            "hunt:unexpected_identity_provider_tokens",
            "hunt:lateral_movement_artifacts",
        ]
        deception_suggestions = [
            "deploy_high_interaction_honeytoken",
            "seed_decoy_credential_path",
        ]
        uncertainty_markers = [
            "correlation_gap_possible",
            "campaign_objective_ambiguous",
            "likely attacker objective differs from current campaign hypothesis",
        ]

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "context": context,
            "alternative_hypotheses": alternatives,
            "hunt_suggestions": hunt_suggestions,
            "deception_suggestions": deception_suggestions,
            "uncertainty_markers": uncertainty_markers,
            # Backward-compatible keys for older consumers.
            "hunt_recommendations": hunt_suggestions,
            "deception_recommendations": deception_suggestions,
            "uncertainty_flags": uncertainty_markers,
            "world_snapshot_size": {
                "entities": len(world_snapshot.get("entities") or []),
                "hotspots": len(world_snapshot.get("hotspots") or []),
            },
        }

@router.get("/loki/hello")
async def hello():
    return {"msg": "Loki is watching"}
