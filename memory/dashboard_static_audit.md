# Dashboard Static Wiring Audit (Refreshed)

Generated: 2026-04-23  
Scope: static router/page wiring evidence from current repository code

---

## Summary

- Backend router modules: **62** (`backend/routers/*.py`)
- Backend route handlers: **697** (`@router.get/post/put/patch/delete/websocket`)
- Router includes in main app: **65** (`app.include_router(...)` in `backend/server.py`)
- Frontend page components: **69** (`frontend/src/pages/*.[jt]sx`)
- Frontend route path declarations: **66** (`path="..."` in `frontend/src/App.js`)

---

## Key observations

1. **Backend route breadth is substantial and active**  
   The API is not centralized into one router; it is distributed across 60+ router modules and included by `backend/server.py`.

2. **Frontend uses workspace consolidation plus redirects**  
   `frontend/src/App.js` routes a large portion of old single-purpose pages into workspace pages (`/command`, `/ai-activity`, `/investigation`, `/detection-engineering`, `/response-operations`, `/email-security`, `/endpoint-mobility`).

3. **Compatibility adapters are explicit**  
   Multiple routes redirect legacy paths (`/dashboard`, `/alerts`, `/threats`, `/agent-commands`, etc.) to current workspace tabs.

4. **Router count and include count differ slightly by design**  
   Include count (65) is greater than router module count (62) because some routers are mounted more than once or with alternate prefixes for compatibility (for example, dual-prefix patterns).

---

## Current top router modules by handler count

| Router file | Approx. handlers |
|---|---:|
| `backend/routers/swarm.py` | 58 |
| `backend/routers/unified_agent.py` | 52 |
| `backend/routers/advanced.py` | 47 |
| `backend/routers/enterprise.py` | 27 |
| `backend/routers/integrations.py` | 23 |
| `backend/routers/deception.py` | 22 |

---

## Residual static wiring risks

1. **High central include density** in `backend/server.py` increases merge pressure and startup coupling risk.
2. **Redirect-heavy frontend strategy** may hide stale deep links if page-local assumptions drift.
3. **Compatibility aliases** require periodic pruning once clients move fully to canonical paths.

---

## Bottom line

Static wiring is broad and coherent in current code. The main maintenance burden is now **complexity management** (central include file and compatibility redirects), not missing route/page wiring.
