from fastapi import APIRouter
from typing import Any

router = APIRouter()

class MetatronService:
    def __init__(self, db: Any = None):
        self.db = db
        if db is not None:
            self.entities = db.world_entities
            self.edges = db.world_edges
            self.campaigns = db.campaigns

    def set_database(self, db: Any):
        """Set Mongo database instance for service."""
        self.__init__(db)

    async def tick(self) -> dict:
        """Perform periodic reasoning cycle (stub)."""
        if self.db is None:
            return {"error": "database not configured"}
        count = await self.entities.count_documents({})
        return {"entities": count}

@router.get("/metatron/hello")
async def hello():
    return {"msg": "Metatron is alive"}

@router.get("/metatron/tick")
async def tick():
    # import here to avoid circular dependencies
    from backend.triune.metatron import MetatronService
    from backend.server import db
    service = MetatronService(db)
    result = await service.tick()
    return result
