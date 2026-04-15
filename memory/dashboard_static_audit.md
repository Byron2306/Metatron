# Dashboard Static Wiring Audit (Updated)

Generated: 2026-04-15  
Method: static repository scan (backend router decorators + frontend page call-sites)

---

## 1) Snapshot Totals

- Backend router files scanned (`backend/routers/*.py`, excluding `dependencies.py`): **61**
- Backend decorated HTTP handlers (`@router.get/post/put/delete/patch`): **694**
- `APIRouter(...)` definitions: **65**
- Frontend pages scanned (`frontend/src/pages`, excluding tests): **69**
- Frontend API call-sites (`fetch` + `axios` patterns): **339**

---

## 2) Frontend-to-Backend Mapping Result

- Statically resolvable unmatched API call-sites: **1**

### Unmatched call-site detail

- `frontend/src/pages/TimelinePage.jsx:58` -> ``${API}/api/timelines/recent?limit=20``
  - Root cause: local API base variable already contains `/api`, producing a double `/api/api/...` path.
  - Backend route exists at `/api/timelines/recent` via `timelines_router`.

---

## 3) Notes on Interpretation

1. Static audit cannot fully resolve all runtime template strings, but catches obvious path construction errors.
2. The single unmatched call-site above is a concrete wiring bug pattern, not a missing backend capability.
3. Existing historical docs that reported smaller route/call-site totals are outdated relative to current repository growth.

---

## 4) Recommended Follow-up

1. Normalize `TimelinePage.jsx` to use a single API-root strategy (avoid `${API}/api/...` when `API` already includes `/api`).
2. Add a lightweight CI check for duplicated `/api/api/` path construction.
3. Re-run this static audit as part of release documentation updates.

