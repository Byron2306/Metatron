# Dashboard Static Wiring Audit

Updated: 2026-04-28
Source basis: `frontend/src/App.js`, `frontend/src/lib/api.js`, and `backend/server.py`.

## Current dashboard reality

The primary dashboard route now redirects into the command workspace:

- `/` -> `/command`
- `/dashboard` -> `/command?tab=dashboard`
- `/alerts` -> `/command?tab=alerts`
- `/threats` -> `/command?tab=threats`
- `/command-center` -> `/command?tab=center`

Dashboard wiring should therefore be audited through `CommandWorkspacePage` and the shared API helpers, not only by scanning a legacy `DashboardPage` assumption.

## Current backend route basis

The active backend is `backend.server:app` on port 8001. It registers most routers under `/api`, while a few routers retain native `/api/v1` prefixes. Dashboard checks should use live route inventory from the FastAPI app when possible.

## Updated static audit summary

| Audit topic | Current finding |
|---|---|
| Root dashboard route | Redirects into `/command?tab=dashboard`. |
| Alerts/threats route behavior | Redirect into command workspace tabs. |
| API base | `frontend/src/lib/api.js` resolves `REACT_APP_BACKEND_URL` or same-origin `/api`. |
| Backend health | `/api/health` on port 8001. |
| Old static counts | Stale; previous 397-route/66-call-site snapshot should be regenerated before use. |

## Current wiring risks

- Static scans can miss workspace-tab API calls if they only inspect path routes.
- Dynamic API paths require sample values for reliable matching.
- Optional integration panels must distinguish unavailable dependencies from backend failure.
- Legacy references to `/api/elasticsearch/status`, `/api/agent/*`, or port 8002 should be treated as drift unless a compatibility route exists.

## Recommended audit method

1. Generate backend routes by importing `backend.server:app` in a controlled environment.
2. Extract frontend API call sites from `frontend/src` and normalize through the shared API helper.
3. Include redirects from `App.js` in the route inventory.
4. Validate dynamic paths with sample parameter dictionaries.
5. Report unmatched calls as true drift, dynamic/parameterized, optional-local, or legacy-compatibility.
