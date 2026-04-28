# Full Pages Wiring and Capability Audit

## Current Code-Logic Snapshot (updated 2026-04-28)

Backend API is FastAPI version `3.0.0` in `backend/server.py`, served on `8001` with health at `/api/health`. The repo has 61 backend router modules plus package init, 32 backend service modules plus package init, 68 JSX frontend pages plus `GraphWorld.tsx`, 68 `<Route` occurrences in `frontend/src/App.js`, unified agent version `2.0.0`, and 63 backend test files. The authenticated frontend hub is `/command`. Root `smoke_test.py` is CAS Shield sidecar code, not a Seraph full-stack health test.


## Current Source-Derived Page Facts

- `frontend/src/pages/` contains 68 `.jsx` page files.
- `frontend/src/pages/GraphWorld.tsx` is also present.
- `frontend/src/App.js` contains 68 `<Route` occurrences including protected route structure and redirects.
- The authenticated root redirects to `/command`.
- Many legacy routes now redirect into workspace tabs instead of rendering their legacy page directly.

## Active Workspace Routing Model

| Workspace | Purpose | Representative redirects |
|---|---|---|
| `/command` | Command dashboard, alerts, threats, command-center tabs | `/dashboard`, `/alerts`, `/threats`, `/command-center` |
| `/investigation` | Intel, correlation, attack paths | `/threat-intel`, `/correlation`, `/attack-paths` |
| `/response-operations` | Response, quarantine, SOAR, EDR | `/quarantine`, `/response`, `/soar`, `/edr` |
| `/detection-engineering` | Sigma, Atomic, MITRE | `/sigma`, `/atomic-validation`, `/mitre-attack` |
| `/email-security` | Email protection and gateway | `/email-protection`, `/email-gateway` |
| `/endpoint-mobility` | Mobile security and MDM | `/mobile-security`, `/mdm` |
| `/unified-agent` | Agent fleet and command operations | `/agents`, `/agent-commands`, `/swarm` |
| `/ai-activity` | AI signals, sessions, intelligence | `/ai-detection`, `/cli-sessions`, `/ai-threats` |

## Audit Interpretation

Earlier static audits that reported 41 pages are stale. Page-file counts alone are not the correct measure of active navigation because `App.js` intentionally keeps compatibility redirects for older paths. Current wiring reviews should use `frontend/src/App.js` as the route source of truth, `frontend/src/pages/` as component inventory, backend OpenAPI/generated routes for API compatibility, and same-origin `/api` fallback behavior plus configured `REACT_APP_BACKEND_URL` behavior.

## Caveat

This document is a source-aligned summary, not a freshly executed browser crawl. Re-run a browser/e2e crawl before using it as release evidence.
