# Full Pages Wiring + Capability Audit (Resolved Vars)

Updated context: 2026-04-27

This audit is retained as historical wiring evidence. The current frontend has moved toward workspace consolidation in `frontend/src/App.js`: several older route-level pages now redirect into `CommandWorkspacePage`, `InvestigationWorkspacePage`, `ResponseOperationsPage`, `EmailSecurityWorkspacePage`, `EndpointMobilityWorkspacePage`, `DetectionEngineeringWorkspacePage`, and `AIActivityWorkspacePage`. Treat the counts below as the latest recorded static scan from the earlier page structure, not as a complete current route inventory.

Current code-logic summary:
- Active backend APIs remain mounted from `backend/server.py` under `/api` plus selected `/api/v1` routers.
- Legacy routes such as `/alerts`, `/threats`, `/soar`, `/edr`, `/email-gateway`, `/email-protection`, `/mdm`, `/mobile-security`, `/agents`, and `/swarm` are compatibility routes that redirect to workspace tabs.
- Zero unmatched call-sites in this historical scan remains useful evidence, but the next audit should regenerate call-site counts against the workspace-oriented route graph.

- Pages scanned: 41
- Pages with API calls: 39
- Pages with zero API calls: 2
- Total API call-sites: 209
- Unmatched call-sites: 0

## Pages with unmatched call-sites
- None

## Pages with zero API calls
- frontend/src/pages/LoginPage.jsx
- frontend/src/pages/SetupGuidePage.jsx

## Buttons without explicit action
- frontend/src/pages/AgentsPage.jsx: 230
- frontend/src/pages/HoneypotsPage.jsx: 276
- frontend/src/pages/ThreatsPage.jsx: 272
- frontend/src/pages/UnifiedAgentPage.jsx: 369, 373, 377, 381

## Unmatched details