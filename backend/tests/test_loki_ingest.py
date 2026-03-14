"""Unit tests for Loki ingestion router."""

import sys, os, types, pathlib, importlib.util
from fastapi import FastAPI
from fastapi.testclient import TestClient
# ensure tests dir is importable so local test utilities can be imported by name
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from test_utils import load_router, load_dependency, load_service


def _load_router(mod_name: str):
    base = pathlib.Path(__file__).resolve().parents[1]
    return load_router(mod_name, base)


def _load_dependency(mod_name: str):
    base = pathlib.Path(__file__).resolve().parents[1]
    return load_dependency(mod_name, base)


def _load_service(mod_name: str):
    base = pathlib.Path(__file__).resolve().parents[1]
    return load_service(mod_name, base)


def _build_app():
    app = FastAPI()
    # ensure services.world_model is available for router imports
    _load_service("world_model")
    loki_router = _load_router("loki")
    app.include_router(loki_router, prefix="/api")
    return app


class FakeColl(dict):
    async def insert_one(self, doc):
        if "id" in doc:
            self[doc["id"]] = doc
        else:
            key = doc.get("source", "") + "->" + doc.get("target", "")
            self[key] = doc

    async def update_one(self, q, u, upsert=False):
        _id = q.get("id")
        self[_id] = {**self.get(_id, {}), **(u.get("$set", {}))}

    async def find_one(self, q, sort=None):
        return self.get(q.get("id"))

    async def count_documents(self, q):
        return len(self)

    async def find(self, q=None, sort=None, limit=None):
        for v in self.values():
            yield v


def test_loki_ingest_detection(monkeypatch):
    deps = _load_dependency("dependencies")
    set_database = deps.set_database
    fake = types.SimpleNamespace()
    fake.world_entities = FakeColl()
    fake.world_edges = FakeColl()
    fake.campaigns = FakeColl()
    set_database(fake)

    app = _build_app()
    client = TestClient(app)

    payload = {"kind": "detection", "id": "d1", "entity_type": "detection", "attributes": {"sig": "x"}}
    r = client.post("/api/loki/ingest", json=payload)
    assert r.status_code == 200
    assert "d1" in fake.world_entities


def test_loki_ingest_edge_and_campaign(monkeypatch):
    deps = _load_dependency("dependencies")
    set_database = deps.set_database
    fake = types.SimpleNamespace()
    fake.world_entities = FakeColl()
    fake.world_edges = FakeColl()
    fake.campaigns = FakeColl()
    set_database(fake)

    app = _build_app()
    client = TestClient(app)

    # edge
    payload = {"kind": "edge", "source": "e1", "target": "e2", "relation": "observed"}
    r = client.post("/api/loki/ingest", json=payload)
    assert r.status_code == 200
    assert any("e1->e2" in k for k in fake.world_edges.keys()) or len(fake.world_edges) > 0

    # campaign
    payload = {"kind": "campaign", "id": "c1", "attributes": {"stage": "initial"}}
    r = client.post("/api/loki/ingest", json=payload)
    assert r.status_code == 200
    assert "c1" in fake.world_entities
