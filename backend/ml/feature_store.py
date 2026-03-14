"""Feature store used by Metatron and other ML consumers."""
from typing import Any, Dict

class FeatureStore:
    def __init__(self, db: Any = None):
        self.db = db
        self.collection = None
        if db is not None:
            self.collection = db.feature_store

    def set_database(self, db: Any):
        self.__init__(db)

    async def store(self, key: str, features: Dict[str, Any]):
        if self.collection is None:
            raise RuntimeError("database not configured")
        await self.collection.update_one({"key": key}, {"$set": {"features": features}}, upsert=True)

    async def fetch(self, key: str) -> Dict[str, Any]:
        if self.collection is None:
            raise RuntimeError("database not configured")
        doc = await self.collection.find_one({"key": key})
        return doc.get("features") if doc else {}
