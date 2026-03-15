import types
import pathlib

from test_utils import ensure_package, load_module_from_folder, load_service




def _bootstrap_triune_package(base):
    triune_dir = base / "triune"
    ensure_package("triune", str(triune_dir))
    load_module_from_folder("triune", triune_dir, "metatron")
    load_module_from_folder("triune", triune_dir, "michael")
    load_module_from_folder("triune", triune_dir, "loki")
    load_module_from_folder("triune", triune_dir, "__init__")

class FakeCursor:
    def __init__(self, docs):
        self.docs = list(docs)

    def limit(self, n):
        return FakeCursor(self.docs[:n])

    async def to_list(self, n):
        return self.docs[:n]

    def __aiter__(self):
        self._i = 0
        return self

    async def __anext__(self):
        if self._i >= len(self.docs):
            raise StopAsyncIteration
        v = self.docs[self._i]
        self._i += 1
        return v


class FakeColl(dict):
    async def insert_one(self, doc):
        key = doc.get("id") or f"k{len(self)+1}"
        self[key] = doc

    async def update_one(self, q, u, upsert=False):
        key = q.get("id")
        current = self.get(key, {"id": key})
        if "$set" in u:
            current.update(u["$set"])
        if "$push" in u:
            for path, value in u["$push"].items():
                top, leaf = path.split(".", 1)
                current.setdefault(top, {})
                current[top].setdefault(leaf, [])
                current[top][leaf].append(value)
        self[key] = current

    async def find_one(self, q, projection=None, sort=None):
        if "id" in q:
            return self.get(q["id"])
        if not self:
            return None
        return next(iter(self.values()))

    async def count_documents(self, q):
        return len(self)

    def find(self, q=None, projection=None, sort=None, limit=0):
        docs = list(self.values())
        if q and "attributes.risk_score" in q:
            docs = [d for d in docs if d.get("attributes", {}).get("risk_score") is not None]
            docs.sort(key=lambda d: d.get("attributes", {}).get("risk_score", 0), reverse=True)
        if limit:
            docs = docs[:limit]
        return FakeCursor(docs)


def _load_services(base):
    load_service("world_model", base)
    _bootstrap_triune_package(base)
    triune_mod = load_service("triune_orchestrator", base)
    events_mod = load_service("world_events", base)
    return triune_mod, events_mod


import pytest


@pytest.mark.asyncio
async def test_emit_world_event_runs_triune_bundle():
    base = pathlib.Path(__file__).resolve().parents[1]
    _, events_mod = _load_services(base)

    fake = types.SimpleNamespace(
        world_entities=FakeColl(),
        world_edges=FakeColl(),
        campaigns=FakeColl(),
        world_events=FakeColl(),
        triune_analysis=FakeColl(),
    )

    fake.world_entities["h1"] = {
        "id": "h1",
        "type": "host",
        "attributes": {"risk_score": 0.9},
    }

    out = await events_mod.emit_world_event(
        fake,
        event_type="detection_ingested",
        entity_refs=["h1"],
        payload={"signal": "x"},
    )

    assert out["event"]["type"] == "detection_ingested"
    assert out["triune"]["event_type"] == "detection_ingested"
    assert out["triune"]["michael"]["ranked"]
    assert out["triune"]["metatron"].get("environment_state")
    assert out["triune"]["michael"]["plan"].get("sector_preparation_plan")
    assert out["triune"]["loki"].get("uncertainty_flags")
    assert fake.world_events


@pytest.mark.asyncio
async def test_emit_world_event_accepts_source_keyword():
    base = pathlib.Path(__file__).resolve().parents[1]
    _, events_mod = _load_services(base)

    fake = types.SimpleNamespace(
        world_entities=FakeColl(),
        world_edges=FakeColl(),
        campaigns=FakeColl(),
        world_events=FakeColl(),
        triune_analysis=FakeColl(),
    )

    out = await events_mod.emit_world_event(
        fake,
        event_type="unit_test_event",
        entity_refs=["entity-1"],
        payload={"ok": True},
        trigger_triune=False,
        source="test.source",
    )

    assert out["event"]["type"] == "unit_test_event"
    assert out["event"]["source"] == "test.source"
    assert out["triune"] is None
