# Dashboard Static Wiring Audit

## Current Code-Logic Snapshot (updated 2026-04-28)

Backend API is FastAPI version `3.0.0` in `backend/server.py`, served on `8001` with health at `/api/health`. The repo has 61 backend router modules plus package init, 32 backend service modules plus package init, 68 JSX frontend pages plus `GraphWorld.tsx`, 68 `<Route` occurrences in `frontend/src/App.js`, unified agent version `2.0.0`, and 63 backend test files. The authenticated frontend hub is `/command`. Root `smoke_test.py` is CAS Shield sidecar code, not a Seraph full-stack health test.


## Current Interpretation

The previous dashboard audit was a point-in-time static scan and is stale for current route/page counts. The dashboard route is now normalized through `/command`, with `/dashboard` redirecting to `/command?tab=dashboard`.

## Current Route Facts

- `frontend/src/App.js` is the authoritative route file.
- Authenticated index route redirects to `/command`.
- Dashboard, alerts, threats, command center, SOAR, EDR, quarantine, correlation, attack paths, email gateway, mobile security, and MDM routes mostly redirect into workspace tabs.
- Backend health is `GET /api/health` on `8001`.

## Static Audit Scope to Re-run

A current audit should check frontend route renderability for active workspace routes, redirect correctness for legacy paths, API call-site compatibility against generated backend routes, degraded-state rendering for optional integrations, and button/action handlers on high-risk response/configuration workflows.

## High-Value Pages to Prioritize

`/command`, `/investigation`, `/response-operations`, `/detection-engineering`, `/unified-agent`, `/email-security`, `/endpoint-mobility`, `/settings`, `/cspm`, `/identity`.

## Caveat

This document records the updated code-logic map. It is not a substitute for a browser-based smoke test or an OpenAPI-backed contract audit.
