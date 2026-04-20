# Metatron Feature Reality Matrix (Rebaselined)

Generated: 2026-04-20  
Scope: code-evidence snapshot of what is implemented now

## Legend

- **PASS**: implemented and wired into active routes or runtime flows.
- **PARTIAL**: implemented but conditional on optional dependencies, credentials, or operational maturity.
- **LIMITED**: present as compatibility or dev path, not the primary production flow.

---

## Current Implementation Matrix

| Domain | Status | Evidence | Notes |
|---|---|---|---|
| API composition and route wiring | PASS | `backend/server.py` | Main app mounts many routers under `/api`; selected routers keep native `/api/v1/*` prefixes (e.g., CSPM, identity). |
| Auth and RBAC | PASS | `backend/routers/auth.py`, `backend/routers/dependencies.py` | JWT auth, role checks, setup token path for first admin bootstrap. |
| Unified agent control plane | PASS | `backend/routers/unified_agent.py` | Registration, heartbeat, commands, alert/state transitions, telemetry projection. |
| Endpoint agent monitors (heavy implementation) | PASS | `unified_agent/core/agent.py` | Broad monitor stack (process/network/registry/dlp/ransomware/rootkit/kernel/email/mobile/etc.). |
| Local dashboard contract | PASS | `unified_agent/ui/web/app.py`, `unified_agent/LOCAL_DASHBOARD_CONTRACT.md` | Canonical local dashboard on port 5000; core-agent fallback UI can use alternate port. |
| Email protection | PASS | `backend/email_protection.py`, `backend/routers/email_protection.py` | SPF/DKIM/DMARC checks, URL and attachment analysis, quarantine/protected-user workflows. |
| Email gateway | PASS | `backend/email_gateway.py`, `backend/routers/email_gateway.py` | SMTP gateway policy path, block/allow lists, quarantine and message processing endpoints. |
| Mobile security | PASS | `backend/mobile_security.py`, `backend/routers/mobile_security.py` | Device lifecycle, app/network/compliance checks, threat tracking. |
| MDM connectors | PASS | `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py` | Intune/JAMF/Workspace ONE/Google Workspace connector framework + device actions. |
| CSPM | PASS | `backend/cspm_engine.py`, `backend/routers/cspm.py` | Multi-provider scans, findings/compliance surfaces, authenticated scan triggers. |
| Threat intel, hunting, response | PASS | `backend/threat_intel.py`, `backend/services/threat_hunting.py`, `backend/threat_response.py` | End-to-end SOC surfaces exist across backend and frontend workspaces. |
| Background tasking | PASS | `backend/celery_app.py`, `backend/tasks/*` | Celery worker/beat paths with Redis broker/backend and world event emission hooks. |
| Frontend routing shell | PASS | `frontend/src/App.js`, `frontend/src/components/Layout.jsx` | Protected route model, workspace navigation, compatibility redirects for legacy paths. |
| Frontend API base consistency | PARTIAL | `frontend/src/lib/api.js`, `frontend/src/context/AuthContext.jsx` | Shared resolver exists, but URL resolution logic is duplicated in multiple modules/pages. |
| `unified_agent/server_api.py` FastAPI side server | LIMITED | `unified_agent/server_api.py` | Useful for standalone/dev workflows, but not the authoritative Mongo-backed control plane. |
| Optional integrations (Falco/Suricata/Zeek/Cuckoo/etc.) | PARTIAL | `docker-compose.yml`, `backend/routers/integrations.py` | Wired and profile-aware, but runtime quality depends on environment tooling and credentials. |

---

## Structural Metrics (from repository state)

- Backend router modules: **62** (`backend/routers/`)
- `app.include_router(...)` registrations in `backend/server.py`: **65**
- Backend service modules: **33** (`backend/services/`)
- Frontend page modules: **70** (`frontend/src/pages/`)
- Unified agent focused test files: **4** (`unified_agent/tests/`)

---

## Reality Notes

1. **Main backend app is `backend.server:app` on port 8001**  
   Confirmed by `backend/Dockerfile` command and `backend/server.py`.

2. **Compose-level dependency behavior is stricter than code-level optionality**  
   In `docker-compose.yml`, backend `depends_on` includes MongoDB, Redis, Elasticsearch, and Ollama.

3. **Two agent surfaces coexist**  
   - Heavy endpoint runtime: `unified_agent/core/agent.py`
   - Desktop/UI core path: `unified_agent/ui/desktop/main.py` + Flask bridge

4. **Legacy documentation drift existed**  
   This matrix supersedes older assumptions that treated some current primary paths as legacy.

---

## Bottom Line

The platform is feature-dense and substantially implemented across endpoint, cloud, identity, email, and mobile domains. Current risk is less about missing modules and more about operational consistency (API base normalization, integration credentials, and cross-surface contract governance).
