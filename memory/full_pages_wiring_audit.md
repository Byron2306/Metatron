# Full Pages Wiring Audit (Current State)

**Last Updated:** 2026-04-14  
**Scope:** Frontend page/workspace routes and backend API wiring compatibility

---

## Summary

- Frontend route definitions in `frontend/src/App.js`: **65**
- Frontend page components in `frontend/src/pages/*.jsx`: **69**
- Backend router registrations in `backend/server.py`: **65** `include_router(...)` calls
- Backend router modules in `backend/routers/*.py`: **60+** files

Important context:

- The frontend is now heavily **workspace-oriented**.
- Multiple legacy feature routes redirect to workspace tabs.
- A strict one-page-to-one-endpoint mapping is no longer the right audit model.

---

## Current Wiring Model

## 1) Frontend route layer

Primary file:

- `frontend/src/App.js`

Observed model:

- `ProtectedRoute` wraps authenticated surfaces.
- Direct routes for selected pages (for example `NetworkTopologyPage`, `UnifiedAgentPage`, `WorldViewPage`).
- Redirect routes for many legacy feature paths (for example `/alerts`, `/threats`, `/email-gateway`, `/mobile-security`) into workspace tabs.

## 2) Backend route layer

Primary file:

- `backend/server.py`

Observed model:

- High-volume `include_router(...)` composition.
- Mixed-prefix routing:
  - `/api/*`
  - `/api/v1/cspm/*`
  - `/api/v1/identity/*`
- Compatibility and duplicate-prefix registrations are used in selected domains.

## 3) Integration implication

Because UI routes can redirect to tabbed workspaces, validation should ensure:

1. route exists and resolves,
2. target workspace fetches expected APIs,
3. auth/permission dependencies allow expected read/write flows.

---

## Known Hotspots for Wiring Drift

1. **Redirect indirection**  
   Route appears valid but can fail at tab-level API fetch.

2. **Compatibility prefixes**  
   Multiple backend prefixes for similar domain surfaces can conceal contract divergence.

3. **Large router volume**  
   Small backend changes can break specific workspace tabs without obvious compile-time errors.

---

## Recommended Audit Method (Going Forward)

Use a three-phase check:

1. **Route resolution audit**  
   Ensure each frontend route resolves to a component or redirect target.

2. **Workspace tab API audit**  
   For each workspace tab, confirm active API calls resolve and expected payload shape is handled.

3. **Auth mode audit**  
   Validate access behavior for:
   - bearer token
   - write/admin permission paths
   - machine-token ingest paths (where relevant)

---

## Conclusion

Wiring is broad and actively maintained, but the architecture has moved from simple page-to-endpoint mapping to workspace composition with redirects and compatibility routes.  
Accurate audits must follow workspace/tab data flows rather than static page-to-route assumptions.
