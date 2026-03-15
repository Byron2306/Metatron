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

    def sort(self, key, direction):
        reverse = direction == -1
        def _get(doc, dotted):
            cur = doc
            for part in dotted.split("."):
                if not isinstance(cur, dict):
                    return None
                cur = cur.get(part)
            return cur
        self.docs = sorted(self.docs, key=lambda d: (_get(d, key) is None, _get(d, key)), reverse=reverse)
        return self

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

    async def update_many(self, q, u):
        modified = 0
        for key, current in list(self.items()):
            if not isinstance(current, dict):
                continue

            matches = True
            for field, expected in (q or {}).items():
                if field == "type" and isinstance(expected, dict) and "$in" in expected:
                    if current.get("type") not in expected["$in"]:
                        matches = False
                        break
                elif field == "attributes.sector" and isinstance(expected, dict) and "$in" in expected:
                    if (current.get("attributes") or {}).get("sector") not in expected["$in"]:
                        matches = False
                        break
                elif current.get(field) != expected:
                    matches = False
                    break

            if not matches:
                continue

            if "$set" in u:
                for skey, sval in u["$set"].items():
                    if "." in skey:
                        top, leaf = skey.split(".", 1)
                        current.setdefault(top, {})
                        if isinstance(current[top], dict):
                            current[top][leaf] = sval
                    else:
                        current[skey] = sval
            self[key] = current
            modified += 1

        return types.SimpleNamespace(modified_count=modified, matched_count=modified)

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

    def aggregate(self, pipeline):
        grouped = {}
        for d in self.values():
            attrs = d.get("attributes", {}) if isinstance(d, dict) else {}
            if "risk_score" not in attrs:
                continue
            sector = attrs.get("sector", "unknown")
            grouped.setdefault(sector, []).append(float(attrs.get("risk_score") or 0.0))
        rows = []
        for sector, vals in grouped.items():
            rows.append({"_id": sector, "avg_risk": sum(vals) / len(vals), "entities": len(vals)})
        rows.sort(key=lambda r: r["avg_risk"], reverse=True)
        return FakeCursor(rows)


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


@pytest.mark.asyncio
async def test_event_classification_separates_persistence_from_trigger():
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
        event_type="agent_heartbeat",
        entity_refs=["a-1"],
        payload={"status": "online"},
        trigger_triune=None,
    )

    assert out["event"]["event_class"] == "local_reflex"
    assert out["event"]["triune_triggered"] is False
    assert out["triune"] is None


@pytest.mark.asyncio
async def test_deception_interaction_runs_beacon_cascade():
    base = pathlib.Path(__file__).resolve().parents[1]
    _, events_mod = _load_services(base)

    fake = types.SimpleNamespace(
        world_entities=FakeColl(),
        world_edges=FakeColl(),
        campaigns=FakeColl(),
        world_events=FakeColl(),
        response_history=FakeColl(),
        triune_analysis=FakeColl(),
        sector_posture=FakeColl(),
        deception_deployments=FakeColl(),
    )
    fake.world_entities["h-fin"] = {
        "id": "h-fin",
        "type": "host",
        "attributes": {"risk_score": 0.91, "sector": "finance"},
    }

    out = await events_mod.emit_world_event(
        fake,
        event_type="deception_interaction",
        entity_refs=["h-fin"],
        payload={"sector": "finance", "decoy_type": "credential"},
        trigger_triune=None,
    )

    cascade = out["triune"]["beacon_cascade"]
    assert cascade["activated"] is True
    assert cascade["predicted_sectors"]
