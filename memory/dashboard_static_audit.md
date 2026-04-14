# Dashboard and Route Wiring Audit (Current Snapshot)

**Last Updated:** 2026-04-14  
**Scope:** Static route and API surface sanity snapshot

---

## Backend Route Surface

- `backend/server.py` `include_router(...)` registrations: **65**
- `backend/routers/*.py` route handlers (`@router.get/post/put/delete/patch`): **high-volume multi-domain surface**
- Mixed prefix strategy:
  - `/api/*` primary
  - `/api/v1/cspm/*`
  - `/api/v1/identity/*`
  - compatibility aliases in selected domains

## Frontend Routing Surface

- Route entries in `frontend/src/App.js`: **65**
- Guard model: `ProtectedRoute` + auth context
- Pattern: workspace consolidation with redirect aliases

## Static Compatibility Observations

1. Frontend route model is workspace/tab-centric and intentionally maps many feature routes into consolidated workspaces.
2. Backend keeps compatibility/alias registrations in some domains, which helps continuity but expands maintenance surface.
3. Static counts should not be interpreted as contract correctness; dynamic API contract tests remain required for enforcement.

## Recommended Audit Automation

For future updates, generate and store:

- OpenAPI endpoint diff vs previous baseline
- frontend fetch URL extraction diff vs backend route inventory
- high-risk route auth dependency verification (mutating endpoints)

This file is intentionally concise and count-oriented; detailed behavioral analysis lives in:

- `memory/FEATURE_REALITY_MATRIX.md`
- `memory/FEATURE_REALITY_REPORT.md`
- `memory/SYSTEM_CRITICAL_EVALUATION.md`
