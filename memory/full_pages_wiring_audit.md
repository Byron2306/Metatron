# Full Pages Wiring + Capability Audit

**Rebaselined:** 2026-04-29
**Scope:** Static review of the current React route shell, workspace pages, and API wiring assumptions.

## Current Summary

The frontend has moved from many standalone pages toward consolidated workspace routes. `frontend/src/App.js` protects all application routes behind `AuthProvider` and `ProtectedRoute`, redirects `/` to `/command`, and preserves older URLs with redirects into workspace tabs. The active operator workspaces are:

- `/command` for dashboard, command center, alerts, and threats.
- `/world` for Metatron/world-model state and graph/event views.
- `/ai-activity` for AI signal detection, intelligence, and CLI sessions.
- `/investigation` for threat intel, correlation, and attack paths.
- `/detection-engineering` for Sigma, MITRE coverage, and atomic validation.
- `/response-operations` for response automation, EDR, SOAR, and quarantine.
- `/email-security` for email protection and gateway views.
- `/endpoint-mobility` for mobile security and MDM connectors.

Additional direct routes remain for network, hunting, honeypots, reports, timeline, audit, settings, Zeek, osquery, ransomware, containers, VPN, honey tokens, zero trust, ML prediction, sandbox, browser isolation, Kibana, advanced services, heatmap, VNS alerts, browser extension, setup guide, tenants, unified agent, CSPM, deception, kernel sensors, secure boot, and identity.

## API Wiring Reality

- API calls are still distributed across page components instead of a single client layer.
- `frontend/src/lib/api.js` provides the preferred base URL behavior, but pages also use local `API` / `API_URL` constants with `axios` or `fetch`.
- Most routes target `/api/...`; selected backend routers expose `/api/v1/...` natively for CSPM, identity, attack paths, secure boot, kernel sensors, and related domains.
- Consolidated redirects mean older slugs such as `/alerts`, `/threats`, `/agents`, `/swarm`, `/agent-commands`, `/edr`, `/soar`, `/quarantine`, `/email-gateway`, and `/mdm` should be treated as compatibility URLs, not primary pages.

## Current Risk Notes

1. Static call-site counts should not be treated as stable because workspace consolidation changes page/component boundaries without necessarily changing functionality.
2. Mixed API base construction remains the main frontend drift risk. Future cleanup should route page calls through `frontend/src/lib/api.js` or a typed service layer.
3. Some imported legacy page components in `App.js` are no longer directly routed because `UnifiedAgentPage` and workspace shells replaced them. This is intentional for compatibility but should be cleaned up if imports become unused.
4. Buttons and chart widgets should be audited functionally in-browser; static button scans overstate risk when actions are attached through custom components or parent tab controls.

## Bottom Line

The frontend route map is coherent and intentionally workspace-oriented. The most important documentation update is to describe active workspace routes and compatibility redirects instead of older raw page-count snapshots.
