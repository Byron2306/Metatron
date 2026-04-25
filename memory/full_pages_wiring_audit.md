# Full Pages Wiring + Capability Audit

**Reviewed:** 2026-04-25  
**Scope:** Static documentation refresh from current route/page organization. This is not a fresh browser runtime test.

## Current Frontend Routing Snapshot

| Item | Count | Evidence |
|---|---:|---|
| `<Route>` entries | 67 | `frontend/src/App.js` |
| Page components imported by App | 43 | `frontend/src/App.js` |
| JSX files in `frontend/src/pages` | 68 | `frontend/src/pages/*.jsx` |

## Current Navigation Model

The frontend is now workspace-oriented. The index route redirects to `/command`, and many historical feature routes redirect into workspace tabs.

Primary workspaces:

- `/command`
- `/world`
- `/ai-activity`
- `/investigation`
- `/detection-engineering`
- `/response-operations`
- `/unified-agent`
- `/email-security`
- `/endpoint-mobility`

Standalone pages remain for network, hunting, honeypots, reports, timeline, audit, settings, Zeek, Osquery, ransomware, containers, VPN, honey tokens, zero trust, ML prediction, sandbox, browser isolation, Kibana, advanced services, heatmap, VNS alerts, browser extension, setup guide, tenants, CSPM, deception, kernel sensors, secure boot, and identity.

## Legacy Route Redirects to Track

Examples of compatibility redirects in `App.js`:

- `/dashboard` -> `/command?tab=dashboard`
- `/alerts` -> `/command?tab=alerts`
- `/threats` -> `/command?tab=threats`
- `/agents` -> `/unified-agent`
- `/quarantine` -> `/response-operations?tab=quarantine`
- `/response` -> `/response-operations?tab=automation`
- `/threat-intel` -> `/investigation?tab=intel`
- `/sigma` -> `/detection-engineering?tab=sigma`
- `/atomic-validation` -> `/detection-engineering?tab=atomic`
- `/mitre-attack` -> `/detection-engineering?tab=mitre`
- `/swarm` -> `/unified-agent`
- `/ai-threats` -> `/ai-activity?tab=intelligence`
- `/email-protection` -> `/email-security?tab=protection`
- `/email-gateway` -> `/email-security?tab=gateway`
- `/mobile-security` -> `/endpoint-mobility?tab=mobile`
- `/mdm` -> `/endpoint-mobility?tab=mdm`

## Backend Route Context

The backend has 61 router modules and 65 router include calls. Most APIs are under `/api`, with selected native or compatibility `/api/v1` routes. Static audits should account for those exceptions before flagging mismatches.

## Known Audit Limitations

- Prior counts such as "41 pages scanned" are historical and no longer describe the route map.
- Static matching cannot prove auth, data-shape, permissions, or runtime service availability.
- Dynamic routes such as prediction-type paths may require route-pattern aware matching.
- Buttons without explicit action handlers should be audited in the workspace pages, not only the legacy page files.

## Recommended Next Audit

1. Generate backend route inventory from the running FastAPI app or router metadata.
2. Extract frontend API call-sites from all workspace and standalone pages.
3. Normalize `/api` and `/api/v1` prefixes, dynamic path parameters, and legacy redirects.
4. Classify each mismatch as fatal, degraded optional integration, or intentionally dynamic.
5. Re-run browser smoke tests against the protected layout after auth setup.
