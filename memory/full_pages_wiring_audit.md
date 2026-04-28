# Full Pages Wiring + Capability Audit

Updated: 2026-04-28
Source basis: direct repository review of `frontend/src/App.js`, `frontend/src/pages/`, and backend route registration.

## Current frontend route model

`frontend/src/App.js` now organizes the product around consolidated workspaces and standalone pages. A raw count of page files is less useful than route behavior, because many legacy routes now redirect into workspace tabs.

## Current static facts

| Item | Current observation |
|---|---:|
| React `*Page` files in `frontend/src/pages` | 63 |
| All files in `frontend/src/pages` | 69 |
| Main route source | `frontend/src/App.js` |
| Default authenticated route | `/` -> `/command` |
| Main API base helper | `frontend/src/lib/api.js` |

## Workspace routes

| Route | Role | Legacy redirects |
|---|---|---|
| `/command` | Command/dashboard/alerts/threats command center | `/dashboard`, `/alerts`, `/threats`, `/command-center` |
| `/ai-activity` | AI signals, intelligence, CLI sessions | `/ai-detection`, `/ai-threats`, `/cli-sessions` |
| `/response-operations` | Quarantine, response automation, EDR, SOAR | `/quarantine`, `/response`, `/edr`, `/soar` |
| `/investigation` | Threat intel, correlation, attack paths | `/threat-intel`, `/correlation`, `/attack-paths` |
| `/detection-engineering` | Sigma, atomic validation, MITRE | `/sigma`, `/atomic-validation`, `/mitre-attack` |
| `/email-security` | Email protection and email gateway | `/email-protection`, `/email-gateway` |
| `/endpoint-mobility` | Mobile security and MDM | `/mobile-security`, `/mdm` |
| `/unified-agent` | Unified agent and swarm/fleet views | `/agents`, `/agent-commands`, `/agent-commands/:agentId`, `/swarm` |

## Standalone routes still present

- `/world`
- `/network`
- `/hunting`
- `/honeypots`
- `/reports`
- `/timeline`
- `/audit`
- `/settings`
- `/zeek`
- `/osquery-fleet`
- `/ransomware`
- `/containers`
- `/vpn`
- `/honey-tokens`
- `/zero-trust`
- `/ml-prediction`
- `/sandbox`
- `/browser-isolation`
- `/kibana`
- `/advanced`
- `/heatmap`
- `/vns-alerts`
- `/browser-extension`
- `/setup-guide`
- `/tenants`
- `/cspm`
- `/deception`
- `/kernel-sensors`
- `/secure-boot`
- `/identity`

## Updated audit interpretation

Older audit snapshots counted 41 pages and 209 call sites. That is stale for the current tree because the frontend now contains 63 `*Page` files and multiple legacy routes redirect into workspace tabs. The correct maintenance approach is to generate route/call-site inventories from source and compare them against FastAPI route exports in CI.

## Known wiring watchpoints

1. Dynamic paths such as ML prediction routes should be validated with actual parameter sets.
2. Workspace tab redirects should be included in route tests so legacy bookmarks remain usable.
3. API clients should prefer the shared API base helper instead of hard-coded host/port strings.
4. Pages for optional services should show degraded states when services or credentials are absent.
5. Local unified-agent UI endpoints are separate from the central backend API and should not be mixed in frontend contract checks.
