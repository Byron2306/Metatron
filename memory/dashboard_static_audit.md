# Dashboard Static Wiring Audit

**Rebaselined:** 2026-04-29  
**Scope:** Dashboard and command-workspace wiring against the current React/FastAPI implementation.

## Current Summary

Dashboard functionality is now part of the consolidated command workspace instead of a purely standalone dashboard route. In `frontend/src/App.js`, `/dashboard` redirects to `/command?tab=dashboard`, while `/alerts` and `/threats` redirect to the same workspace with their corresponding tabs. `CommandWorkspacePage` is therefore the primary navigation surface for SOC summary, command center, alert review, and threat review workflows.

## Backend Contract

The backend remains a FastAPI application rooted at `backend/server.py`. Dashboard-adjacent routes are mounted under `/api` through routers such as:

- `backend/routers/dashboard.py`
- `backend/routers/alerts.py`
- `backend/routers/threats.py`
- `backend/routers/agent_commands.py`
- `backend/routers/swarm.py`
- `backend/routers/unified_agent.py`

The dashboard should be documented as API-backed but tolerant of partial data when optional integrations are disabled.

## Current Wiring Notes

- `DashboardPage.jsx` still represents the dashboard tab and calls dashboard stats/seed endpoints.
- Alerts and threats are compatibility routes into the command workspace rather than first-class top-level page URLs.
- Command/agent operations are increasingly gated by governance paths when commands become high-impact actions.
- Optional service state should be surfaced as degraded status rather than fatal dashboard failure.

## Known Risks

1. Dashboard widgets rely on page-local data fetching patterns and may drift from backend response shapes without contract tests.
2. API path construction is not fully normalized across command, alert, threat, and agent pages.
3. Static scans should be supplemented with runtime smoke tests because redirects and workspace tabs hide some effective routes from simple file-level audits.

## Bottom Line

The dashboard is no longer best described by raw matched/unmatched call-site counts. It is the dashboard tab inside a broader command workspace backed by `/api/dashboard`, `/api/alerts`, `/api/threats`, swarm, unified-agent, and agent-command APIs.
