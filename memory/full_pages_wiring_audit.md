# Full Pages Wiring + Capability Audit (2026-04-23 Refresh)

## Scope and method

- Frontend page surface reviewed from `frontend/src/pages/*`.
- Route shell reviewed from `frontend/src/App.js`.
- Backend route registration and endpoint families reviewed from `backend/server.py` and `backend/routers/*`.
- Focus: route availability, major workspace redirects, and API-family alignment.

---

## High-level results

- **Frontend page modules present:** 69
- **Frontend route paths declared in App shell:** 66 (`path="..."` entries)
- **Backend routers registered in server:** 65 `include_router(...)` calls
- **Backend router modules present:** 62
- **Backend route handlers in router modules:** 697

Interpretation: frontend and backend are both large and actively wired; most legacy paths now resolve through workspace redirects instead of hard failures.

---

## Current frontend route model

The app uses a **workspace-first navigation model**:

- `/command` (primary command workspace)
- `/investigation`
- `/response-operations`
- `/detection-engineering`
- `/email-security`
- `/endpoint-mobility`
- `/ai-activity`
- `/world`

Many legacy direct pages are intentionally mapped with `<Navigate ...>` redirects into those workspaces (for example old `/alerts`, `/threats`, `/quarantine`, `/mdm`, `/email-gateway` style paths).

This preserves backward URL compatibility while consolidating UX around a smaller set of coordinated workspaces.

---

## Backend/API family alignment

Core families are registered and reachable through active routers:

- Auth/users and permission dependencies
- Threat, alert, timeline, reports, audit
- Unified agent lifecycle, telemetry, command, deployment, EDM rollout
- Swarm + agent command center planes
- Response, quarantine, SOAR, ransomware
- AI threat intelligence, advanced services, triune/world ingest
- Email protection + email gateway
- Mobile security + MDM connectors
- CSPM, identity, governance, enterprise controls
- VPN, Zeek, osquery, sigma, atomic validation

No broad API-family gaps were identified at the registration level.

---

## Known wiring characteristics (important context)

1. `backend/server.py` is still the central include hub (dense wiring file).
2. Some route groups are intentionally dual-exposed for compatibility (`/api` and selected `/api/v1` families).
3. Frontend compatibility relies heavily on redirect mapping in `App.js`; this is by design, not accidental drift.
4. Optional-integration pages can render partial/degraded states depending on environment services (Cuckoo, Falco, Suricata, Zeek, Ollama, etc.).

---

## Practical conclusion

At route-wiring level, the platform is **well-connected and operationally broad**. Remaining quality risk is mostly not “missing routes,” but **behavioral consistency across optional integrations and dense backend composition**.
