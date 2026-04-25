# Dashboard Static Wiring Audit

**Reviewed:** 2026-04-25  
**Scope:** Static wiring context for the current React workspace shell and backend route mesh.

## Current State

The dashboard is no longer a single authoritative page. `frontend/src/App.js` redirects `/dashboard` to `/command?tab=dashboard`, and the platform shell is organized around workspace pages.

Current static inventory:

| Item | Count | Evidence |
|---|---:|---|
| Backend router modules | 61 | `backend/routers/*.py` |
| Backend router include calls | 65 | `backend/server.py` |
| Frontend route entries | 67 | `frontend/src/App.js` |
| App-imported page components | 43 | `frontend/src/App.js` |
| Page JSX files | 68 | `frontend/src/pages/*.jsx` |

## Audit Interpretation

Older dashboard-only static audits are useful history, but they should not be used as current coverage claims. Current wiring checks must include:

- `CommandWorkspacePage.jsx` for dashboard, alerts, threats, and command-center tabs;
- `AIActivityWorkspacePage.jsx` for AI detection/activity tabs;
- `InvestigationWorkspacePage.jsx` for intel, paths, and correlation tabs;
- `DetectionEngineeringWorkspacePage.jsx` for Sigma, Atomic, and MITRE tabs;
- `ResponseOperationsPage.jsx` for EDR, quarantine, SOAR, and response tabs;
- `EmailSecurityWorkspacePage.jsx` for protection and gateway tabs;
- `EndpointMobilityWorkspacePage.jsx` for mobile and MDM tabs;
- direct pages still routed from `App.js`.

## Backend Prefix Rules

- Most routers mount at `/api`.
- CSPM and several tier-1 routes carry `/api/v1` prefixes.
- Identity is included without an extra `/api` prefix because the router carries its own prefix.
- Deception is mounted under both `/api` and `/api/v1` for compatibility.
- Raw WebSockets are under `/ws/*`.

## Known Static Audit Risks

- Dynamic API paths need pattern matching rather than exact string matching.
- Query-tab redirects can hide API call-sites from legacy route scans.
- Optional integrations may have valid routes but degraded runtime state.
- Auth-protected pages can appear wired statically while failing without seed/setup credentials.

## Current Bottom Line

The static wiring target is now the **workspace shell plus route mesh**, not the historical dashboard page. Any future audit should be regenerated from current code rather than carrying forward older page and button counts.
