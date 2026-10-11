import pytest

from observation_db_helpers import Database


@pytest.mark.asyncio
async def test_aatr_readiness_reports_seeded_db_backed_registry(monkeypatch):
    from backend.services import aatr

    monkeypatch.setattr(aatr, "_aatr", None)
    monkeypatch.setenv("ENVIRONMENT", "lab")

    db = Database()
    await aatr.init_aatr(db)

    readiness = await aatr.get_aatr_readiness(db)

    assert readiness["schema"] == "seraph.aatr.readiness.v1"
    assert readiness["ready"] is True
    assert readiness["initialized"] is True
    assert readiness["db_backed"] is True
    assert readiness["mode"] == "lab"
    assert readiness["production_like"] is False
    assert readiness["registry_entries"] >= 1
    assert readiness["db_entries"] == readiness["registry_entries"]
    assert readiness["unsafe_reasons"] == []


@pytest.mark.asyncio
async def test_aatr_production_readiness_refuses_uninitialized_registry(monkeypatch):
    from backend.services import aatr

    monkeypatch.setattr(aatr, "_aatr", None)
    monkeypatch.setenv("ENVIRONMENT", "production")

    with pytest.raises(RuntimeError, match="AATR readiness check failed"):
        await aatr.require_aatr_ready(Database())


@pytest.mark.asyncio
async def test_aatr_readiness_reports_db_seed_failures(monkeypatch):
    from backend.services import aatr

    monkeypatch.setattr(aatr, "_aatr", None)
    monkeypatch.setenv("ENVIRONMENT", "lab")

    db = Database()
    await aatr.init_aatr(db)
    await db.aatr_entries.delete_many({})

    readiness = await aatr.get_aatr_readiness(db)

    assert readiness["ready"] is False
    assert readiness["initialized"] is True
    assert readiness["db_backed"] is False
    assert "aatr_db_seed_missing" in readiness["unsafe_reasons"]
