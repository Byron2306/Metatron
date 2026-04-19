# Full Pages Wiring + Capability Audit (Updated April 2026)

## Scope and method

This audit was regenerated from current code in:

- `frontend/src/pages/*.{js,jsx}`
- `backend/server.py`
- `backend/routers/*.py`

Checks performed:

1. Count frontend page modules and API-bearing page modules.
2. Extract frontend `/api/...` call-sites.
3. Build backend route surface from router decorators + mounted prefixes.
4. Compare call-sites to backend paths (literal + dynamic-safe normalization).

## Current snapshot

- Frontend page modules scanned: **68**
- Page modules with API usage: **58**
- Page modules with no direct API usage: **10**
- Frontend `/api/...` call-sites extracted: **148**
- Backend route paths resolved (mounted): **660**
- Matched frontend call-sites: **142**
- Unmatched frontend call-sites: **6**

## Pages with no direct API calls

These pages currently act as layout/workspace shells or static wrappers:

- `frontend/src/pages/AIActivityWorkspacePage.jsx`
- `frontend/src/pages/CommandWorkspacePage.jsx`
- `frontend/src/pages/DetectionEngineeringWorkspacePage.jsx`
- `frontend/src/pages/EmailSecurityWorkspacePage.jsx`
- `frontend/src/pages/EndpointMobilityWorkspacePage.jsx`
- `frontend/src/pages/InvestigationWorkspacePage.jsx`
- `frontend/src/pages/JobCard.jsx`
- `frontend/src/pages/LoginPage.jsx`
- `frontend/src/pages/ResponseOperationsPage.jsx`
- `frontend/src/pages/WorldGraph.jsx`

## Unmatched call-sites (current)

1. `frontend/src/pages/AIDetectionPage.jsx` -> `/api/data` (4 occurrences)
2. `frontend/src/pages/DeceptionPage.jsx` -> `/api/login`
3. `frontend/src/pages/ZeroTrustPage.jsx` -> `/api/admin/users`

## Interpretation

- The page-to-API wiring coverage is high (**142/148 matched**).
- Remaining mismatches appear to be legacy placeholders or stale endpoints rather than core platform breakage.
- Workspace-style pages are intentionally thin wrappers in the current frontend architecture and should not be treated as missing wiring defects by default.

## Recommended follow-ups

1. Replace `/api/data` usages in `AIDetectionPage.jsx` with routed data sources from existing `ai`, `ai-threats`, or `dashboard` endpoints.
2. Replace `DeceptionPage` `/api/login` dependency with the shared auth flow used by `AuthContext`.
3. Replace `ZeroTrustPage` `/api/admin/users` with `/api/users` + role/permission gate compatibility.
4. Keep this audit as a static contract check in CI to catch future drift.
