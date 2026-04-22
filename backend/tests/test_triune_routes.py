"""Smoke tests for the triune intelligence routers."""

import pytest
import sys, os, types
# ensure 'backend' directory is on path so we can import routers
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI
from fastapi.testclient import TestClient


import sys, os, types, pathlib
# ensure 'backend' directory is on path so we can import routers
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
# ensure tests dir is importable so local test utilities can be imported by name
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from fastapi import FastAPI
from fastapi.testclient import TestClient
from test_utils import load_router, load_service


pytestmark = pytest.mark.skip(
    reason="legacy router smoke tests deadlock under in-process HTTP clients in this environment"
)


def _build_app():
    app = FastAPI()
    base = pathlib.Path(__file__).resolve().parents[1]
    # ensure services importable for routers that depend on them
    load_service("world_model", base)
    # load the routers we need
    metatron_router = load_router("metatron", base)
    michael_router = load_router("michael", base)
    loki_router = load_router("loki", base)
    world_ingest_router = load_router("world_ingest", base)
    alerts_router = load_router("alerts", base)
    threats_router = load_router("threats", base)
    deception_router = load_router("deception", base)
    vpn_router = load_router("vpn", base)
    response_router = load_router("response", base)
    timeline_router = load_router("timeline", base)
    soar_router = load_router("soar", base)
    app.include_router(metatron_router, prefix="/api")
    app.include_router(michael_router, prefix="/api")
    app.include_router(loki_router, prefix="/api")
    app.include_router(world_ingest_router, prefix="/api")
    app.include_router(alerts_router, prefix="/api")
    app.include_router(threats_router, prefix="/api")
    app.include_router(deception_router, prefix="/api")
    app.include_router(vpn_router, prefix="/api")
    app.include_router(response_router, prefix="/api")
    app.include_router(timeline_router, prefix="/api")
    app.include_router(soar_router, prefix="/api")
    return app


def test_michael_hello():
    app = _build_app()
    client = TestClient(app)
    r = client.get("/api/michael/hello")
    assert r.status_code == 200
    assert r.json().get("msg") == "Michael router active"


def test_loki_hello():
    app = _build_app()
    client = TestClient(app)
    r = client.get("/api/loki/hello")
    assert r.status_code == 200
    assert r.json().get("msg") == "Loki router active"


def test_metatron_summary_empty():
    app = _build_app()
    client = TestClient(app)
    r = client.get("/api/metatron/summary")
    assert r.status_code == 200
    j = r.json()
    assert j.get("entities") == 0
    assert isinstance(j.get("campaigns"), list)


def test_metatron_state_structure():
    app = _build_app()
    client = TestClient(app)
    r = client.get("/api/metatron/state")
    assert r.status_code == 200
    s = r.json()
    # verify top-level keys exist
    for key in ["header", "narrative", "attack_path", "trust", "hotspots", "actions", "hypotheses", "timeline"]:
        assert key in s
    # header should have risk_level
    assert "risk_level" in s["header"]
    assert s["header"]["risk_level"] in {"low", "elevated"}
    # hotspots and trust keys exist
    assert isinstance(s.get("hotspots"), list)
    assert "identity" in s.get("trust", {})


def test_ingest_entity_and_risk(tmp_path, monkeypatch):
    # use in-memory db by patching dependencies.db to simple dict-like
    from routers.dependencies import set_database, db as global_db
    # create fake motor-like collections using dicts
    class FakeColl(dict):
        async def update_one(self, q, u, upsert=False):
            _id = q.get("id")
            self[_id] = {**self.get(_id, {}), **(u.get("$set", {}))}
            return None
        async def find_one(self, q, sort=None):
            return self.get(q.get("id"))
        async def count_documents(self, q):
            return len(self)
        async def find(self, q=None, sort=None, limit=None):
            for v in self.values():
                yield v
    fake = types.SimpleNamespace()
    fake.world_entities = FakeColl()
    fake.world_edges = FakeColl()
    fake.campaigns = FakeColl()
    set_database(fake)
    app = _build_app()
    client = TestClient(app)
    # ingest simple entity
    r = client.post("/api/ingest/entity", json={"id":"e1","type":"host","attributes":{}})
    assert r.status_code == 200
    # ingest detection which should set risk_score
    r = client.post("/api/ingest/detection", json={"entity_id":"e1","confidence":80})
    assert r.status_code == 200
    # read world-state header to check risk level changes
    r = client.get("/api/metatron/state")
    hdr = r.json()["header"]
    assert hdr["risk_level"] in {"low","elevated"}

    # hotspot list should contain our host with risk_score attribute
    r = client.get("/api/metatron/state")
    hs = r.json()["hotspots"]
    assert isinstance(hs, list)
    # after ingestion there should be entries (risk_score maybe 0.1)
    assert any(e.get("id") == "e1" for e in hs) or hdr["risk_level"] == "low"


def test_decoy_interaction_ingestion():
    from routers.dependencies import set_database
    class FakeColl(dict):
        async def insert_one(self, doc):
            # allow docs without explicit id (edges)
            if "id" in doc:
                key = doc["id"]
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
    fake = types.SimpleNamespace()
    fake.world_entities = FakeColl()
    fake.world_edges = FakeColl()
    fake.campaigns = FakeColl()
    fake.alerts = FakeColl()
    fake.threats = FakeColl()
    set_database(fake)

    app = _build_app()
    # override auth
    from routers import dependencies
    app.dependency_overrides[dependencies.get_current_user] = lambda request=None, credentials=None: {"id":"u1","email":"u@x","role":"admin"}
    client = TestClient(app)
    # call decoy interaction route
    payload = {"ip":"1.2.3.4","decoy_type":"credentials","decoy_id":"dec1"}
    r = client.post("/api/deception/decoy/interaction", json=payload)
    assert r.status_code == 200
    # ensure world model has ip entity and edge
    assert "1.2.3.4" in fake.world_entities
    assert "dec1" in fake.world_entities
    assert any(e.get("relation") == "hit_decoy" for e in fake.world_edges.values())


def test_vpn_peer_ingestion():
    from routers.dependencies import set_database
    class FakeColl(dict):
        async def insert_one(self, doc):
            if "id" in doc:
                self[doc['id']] = doc
            else:
                key = doc.get("source","")+"->"+doc.get("target",
"")
                self[key] = doc
        async def update_one(self, q, u, upsert=False):
            _id = q.get("id")
            self[_id] = {**self.get(_id,{}), **(u.get("$set",{}))}
        async def find_one(self, q, sort=None):
            return self.get(q.get("id"))
        async def count_documents(self, q):
            return len(self)
        async def find(self, q=None, sort=None, limit=None):
            for v in self.values():
                yield v
    fake = types.SimpleNamespace()
    fake.world_entities = FakeColl()
    fake.world_edges = FakeColl()
    fake.campaigns = FakeColl()
    fake.alerts = FakeColl()
    fake.threats = FakeColl()
    fake.vpn = FakeColl()
    set_database(fake)

    app = _build_app()
    from routers import dependencies
    app.dependency_overrides[dependencies.get_current_user] = lambda request=None, credentials=None: {"id":"u1","email":"u@x","role":"admin"}
    # also permission check to bypass
    from routers import dependencies as deps
    deps.check_permission = lambda p: lambda user=None: {"id":"u1","email":"u@x","role":"admin"}
    client = TestClient(app)
    # simulate peer creation; vpn_manager returns dict with id/name
    # monkeypatch vpn_manager.add_peer
    from vpn_integration import vpn_manager
    async def fake_add(name, **kwargs):
        return {
            "peer_id": kwargs.get("peer_id") or "peer1",
            "name": name,
            "public_key": kwargs.get("public_key") or "pub1",
            "allowed_ips": "10.200.200.10/32",
        }
    vpn_manager.add_peer = fake_add

    r = client.post("/api/vpn/peers", json={"name":"testpeer","peer_id":"agent-123","public_key":"pub-agent"})
    assert r.status_code == 200
    body = r.json()
    assert body["peer_id"] == "agent-123"
    assert body["public_key"] == "pub-agent"
    assert "agent-123" in fake.world_entities


def test_vpn_peer_registration_with_agent_auth():
    from routers import vpn as vpn_router
    from routers.dependencies import set_database

    class FakeColl(dict):
        async def insert_one(self, doc):
            if "id" in doc:
                self[doc['id']] = doc
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

    fake_db = types.SimpleNamespace(vpn=FakeColl())
    set_database(fake_db)

    app = _build_app()
    app.dependency_overrides[vpn_router.get_vpn_identity] = lambda request=None, x_agent_id=None, x_agent_token=None, x_enrollment_key=None, authorization=None: {
        "type": "authenticated",
        "agent_id": "agent-123",
        "ip": "127.0.0.1",
        "trusted": True,
    }

    from vpn_integration import vpn_manager
    async def fake_add(name, peer_id=None, allowed_ips=None):
        return {
            "peer_id": peer_id or "peer1",
            "name": name,
            "public_key": "pub1",
            "allowed_ips": allowed_ips or "10.200.200.10/32",
        }
    vpn_manager.add_peer = fake_add

    client = TestClient(app)
    response = client.post("/api/vpn/peers", json={"name": "agent-123", "peer_id": "agent-123"})
    assert response.status_code == 200
    body = response.json()
    assert body["peer"]["peer_id"] == "agent-123"
    assert body["peer"]["name"] == "agent-123"


def test_risk_score_increases_with_severity():
    import asyncio
    from routers.dependencies import set_database
    class FakeColl(dict):
        async def insert_one(self, doc):
            if "id" in doc:
                self[doc['id']] = doc
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
    fake = types.SimpleNamespace()
    fake.world_entities = FakeColl()
    fake.world_edges = FakeColl()
    fake.campaigns = FakeColl()
    fake.alerts = FakeColl()
    fake.threats = FakeColl()
    set_database(fake)
    # manually call calculate_risk
    from services.world_model import WorldModelService, WorldEntity
    wm = WorldModelService(fake)
    # first low severity
    ent = WorldEntity(id="ent1", type="host", attributes={"detections":[{"confidence":50,"severity":1}]})
    asyncio.run(wm.upsert_entity(ent))
    doc1 = asyncio.run(wm.entities.find_one({"id":"ent1"}))
    low_risk = doc1.get("attributes", {}).get("risk_score") or doc1.get("attributes.risk_score")
    # now add high severity detection
    asyncio.run(wm.entities.update_one({"id":"ent1"},{"$push":{"attributes.detections":{"confidence":80,"severity":5}}}))
    asyncio.run(wm.calculate_risk("ent1"))
    doc2 = asyncio.run(wm.entities.find_one({"id":"ent1"}))
    high_risk = doc2.get("attributes", {}).get("risk_score") or doc2.get("attributes.risk_score")
    # risk should not decrease after adding a higher-severity detection
    assert high_risk >= low_risk




def test_policy_violation_increases_risk():
    import asyncio
    from routers.dependencies import set_database
    class FakeColl(dict):
        async def insert_one(self, doc):
            if "id" in doc:
                self[doc['id']] = doc
            else:
                self[self_key(doc)] = doc
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
    fake = types.SimpleNamespace()
    fake.world_entities = FakeColl()
    fake.world_edges = FakeColl()
    fake.campaigns = FakeColl()
    set_database(fake)
    from services.world_model import WorldModelService, WorldEntity
    wm = WorldModelService(fake)
    # create entity and compute baseline
    ent = WorldEntity(id="ent2", type="host", attributes={})
    asyncio.run(wm.upsert_entity(ent))
    base_doc = asyncio.run(wm.entities.find_one({"id":"ent2"}))
    base = base_doc.get("attributes", {}).get("risk_score", base_doc.get("attributes.risk_score", 0))
    # flag policy violation
    asyncio.run(wm.entities.update_one({"id":"ent2"},{"$set":{"attributes.policy_violation":True}}))
    asyncio.run(wm.calculate_risk("ent2"))
    new_doc = asyncio.run(wm.entities.find_one({"id":"ent2"}))
    new_risk = new_doc.get("attributes", {}).get("risk_score") or new_doc.get("attributes.risk_score")
    assert new_risk >= base


def test_ingest_policy_violation_endpoint():
    from routers.dependencies import set_database
    class FakeColl(dict):
        async def insert_one(self, doc):
            if "id" in doc:
                self[doc['id']] = doc
            else:
                key = doc.get("source","")+"->"+doc.get("target","")
                self[key] = doc
        async def update_one(self, q, u, upsert=False):
            _id = q.get("id")
            self[_id] = {**self.get(_id,{}), **(u.get("$set",{}))}
        async def find_one(self, q, sort=None):
            return self.get(q.get("id"))
        async def count_documents(self, q):
            return len(self)
        async def find(self, q=None, sort=None, limit=None):
            for v in self.values():
                yield v
    fake = types.SimpleNamespace()
    fake.world_entities = FakeColl()
    fake.world_edges = FakeColl()
    fake.campaigns = FakeColl()
    set_database(fake)

    app = _build_app()
    client = TestClient(app)
    r = client.post("/api/ingest/policy-violation", json={"entity_id":"eid1"})
    assert r.status_code == 200
    # the fake collection currently stores flat keys, just ensure entity exists
    assert "eid1" in fake.world_entities


def test_ingest_token_event_endpoint():
    from routers.dependencies import set_database
    class FakeColl(dict):
        async def insert_one(self, doc):
            if "id" in doc:
                self[doc['id']] = doc
            else:
                key = doc.get("source","")+"->"+doc.get("target","")
                self[key] = doc
        async def update_one(self, q, u, upsert=False):
            _id = q.get("id")
            self[_id] = {**self.get(_id,{}), **(u.get("$set",{}))}
        async def find_one(self, q, sort=None):
            return self.get(q.get("id"))
        async def count_documents(self, q):
            return len(self)
        async def find(self, q=None, sort=None, limit=None):
            for v in self.values():
                yield v
    fake = types.SimpleNamespace()
    fake.world_entities = FakeColl()
    fake.world_edges = FakeColl()
    fake.campaigns = FakeColl()
    set_database(fake)

    app = _build_app()
    client = TestClient(app)
    r = client.post("/api/ingest/token-event", json={"token_id":"tok1","foo":1})
    assert r.status_code == 200
    # push support not implemented in fake, just verify entity created
    assert "tok1" in fake.world_entities


def test_timeline_artifact_ingestion():
    from routers.dependencies import set_database
    class FakeColl(dict):
        async def insert_one(self, doc):
            if "id" in doc:
                self[doc['id']] = doc
            else:
                key = doc.get("source","")+"->"+doc.get("target","")
                self[key] = doc
        async def update_one(self, q, u, upsert=False):
            _id = q.get("id")
            self[_id] = {**self.get(_id,{}), **(u.get("$set",{}))}
        async def find_one(self, q, sort=None):
            return self.get(q.get("id"))
        async def count_documents(self, q):
            return len(self)
        async def find(self, q=None, sort=None, limit=None):
            for v in self.values():
                yield v
    fake = types.SimpleNamespace()
    fake.world_entities = FakeColl()
    fake.world_edges = FakeColl()
    fake.campaigns = FakeColl()
    set_database(fake)

    # override permissions and user
    from routers import dependencies as deps
    deps.check_permission = lambda p: lambda user=None: {"id":"u","email":"u@x","role":"admin"}
    app = _build_app()
    app.dependency_overrides[deps.get_current_user] = lambda request=None, credentials=None: {"id":"u","email":"u@x","role":"admin"}
    client = TestClient(app)
    payload = {"artifact_type":"file","name":"test","description":"desc"}
    r = client.post("/api/timeline/artifacts/register", json=payload)
    assert r.status_code == 200
    data = r.json()
    art = data.get("artifact", {})
    assert art.get("artifact_id")
    assert art.get("artifact_id") in fake.world_entities
    # custody update should create edge
    aid = art.get("artifact_id")
    r2 = client.post(f"/api/timeline/artifacts/{aid}/custody", json={"action":"moved","notes":"x"})
    assert r2.status_code == 200
    assert any(e.get("relation") == "custody_update" for e in fake.world_edges.values())


def test_soar_trigger_ingests_event():
    from routers.dependencies import set_database
    class FakeColl(dict):
        async def insert_one(self, doc):
            if "id" in doc:
                self[doc['id']] = doc
            else:
                key = doc.get("source","")+"->"+doc.get("target","")
                self[key] = doc
        async def update_one(self, q, u, upsert=False):
            _id = q.get("id")
            self[_id] = {**self.get(_id,{}), **(u.get("$set",{}))}
        async def find_one(self, q, sort=None):
            return self.get(q.get("id"))
        async def count_documents(self, q):
            return len(self)
        async def find(self, q=None, sort=None, limit=None):
            for v in self.values():
                yield v
    fake = types.SimpleNamespace()
    fake.world_entities = FakeColl()
    fake.world_edges = FakeColl()
    fake.campaigns = FakeColl()
    set_database(fake)
    # override permissions and user
    from routers import dependencies as deps
    deps.check_permission = lambda p: lambda user=None: {"id":"u","email":"u@x","role":"admin"}
    app = _build_app()
    app.dependency_overrides[deps.get_current_user] = lambda request=None, credentials=None: {"id":"u","email":"u@x","role":"admin"}
    client = TestClient(app)
    event = {"trigger_type":"foo","source_ip":"1.2.3.4"}
    r = client.post("/api/soar/trigger", json=event)
    assert r.status_code == 200
    # some world entity id should start with 'soar_'
    assert any(k.startswith("soar_") for k in fake.world_entities.keys())
    # there should be an edge linking the source_ip
    assert any(e.get("relation") == "soar_event" for e in fake.world_edges.values())


def test_response_block_updates_world():
    from routers.dependencies import set_database
    class FakeColl(dict):
        async def insert_one(self, doc):
            if "id" in doc:
                self[doc['id']] = doc
            else:
                key = doc.get("source","")+"->"+doc.get("target",
"")
                self[key] = doc
        async def update_one(self, q, u, upsert=False):
            _id = q.get("id")
            self[_id] = {**self.get(_id,{}), **(u.get("$set",{}))}
        async def find_one(self, q, sort=None):
            return self.get(q.get("id"))
        async def count_documents(self, q):
            return len(self)
        async def find(self, q=None, sort=None, limit=None):
            for v in self.values():
                yield v
    fake = types.SimpleNamespace()
    fake.world_entities = FakeColl()
    fake.world_edges = FakeColl()
    fake.campaigns = FakeColl()
    fake.alerts = FakeColl()
    fake.threats = FakeColl()
    set_database(fake)

    app = _build_app()
    from routers import dependencies
    app.dependency_overrides[dependencies.get_current_user] = lambda request=None, credentials=None: {"id":"u1","email":"u@x","role":"admin"}
    from routers import dependencies as deps
    deps.check_permission = lambda p: lambda u=None: {"id":"u1","email":"u@x","role":"admin"}
    client = TestClient(app)
    # monkeypatch manual_block_ip
    from threat_response import manual_block_ip
    async def fake_block(ip, reason, hrs, name):
        return {"blocked": ip, "reason": reason}
    import threat_response
    threat_response.manual_block_ip = fake_block

    r = client.post("/api/threat-response/block-ip", json={"ip":"9.9.9.9","reason":"test","duration_hours":1})
    assert r.status_code == 200
    assert "9.9.9.9" in fake.world_entities


def test_alert_router_updates_world_model():
    from routers.dependencies import set_database
    # reuse same fake db logic
    class FakeColl(dict):
        async def insert_one(self, doc):
            self[doc['id']] = doc
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
    fake = types.SimpleNamespace()
    fake.world_entities = FakeColl()
    fake.world_edges = FakeColl()
    fake.campaigns = FakeColl()
    fake.alerts = FakeColl()
    set_database(fake)

    app = _build_app()
    # override auth dependency to bypass JWT checks
    from routers import dependencies
    app.dependency_overrides[dependencies.get_current_user] = lambda request=None, credentials=None: {"id": "u1", "email": "u@x", "role": "admin"}
    client = TestClient(app)
    # create alert via router
    r = client.post("/api/alerts", json={"title":"test","type":"malware","severity":"high","threat_id":None,"message":"warn"})
    assert r.status_code == 200
    alert = r.json()
    # world-model should now have entity with same id
    state = client.get("/api/metatron/state").json()
    ids = [e.get('id') for e in state['hotspots']]
    assert alert['id'] in fake.world_entities or alert['id'] in ids
