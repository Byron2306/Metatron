# Metatron Run-Mode Contract

**Updated:** 2026-04-30  
**Purpose:** Define required services, optional/degraded integrations, launch modes, and validation checks that match the current repository code.

---

## 1. Required Core

For the dashboard and API to be considered basically healthy:

- `mongodb`
- `backend`
- `frontend`

The backend process is `uvicorn backend.server:app` and listens on port `8001` in the current Dockerfile/server configuration.

### Compose-default additions

The default `docker-compose.yml` graph also includes:

- `redis`
- `celery-worker`
- `celery-beat`
- `elasticsearch`
- `kibana`
- `ollama`
- `wireguard`
- `nginx`

Operators can run a smaller hand-selected stack, but docs should distinguish that from the default compose graph. Redis is required for Celery worker/beat behavior in compose.

---

## 2. Optional / Degraded Integrations

The UI and backend should remain usable when these are unavailable, but related features may show warnings, empty states, or degraded status:

- WireGuard VPN
- Elasticsearch and Kibana
- Ollama/local LLM
- External SIEM forwarding
- SMTP/MTA relay for email gateway
- MDM provider credentials/APIs
- Cloud provider credentials for CSPM
- Cuckoo sandbox
- Trivy, Falco, Suricata, Zeek, osquery logs
- Twilio, SendGrid, Slack webhooks

---

## 3. Profile-Based Optional Integrations

### security profile

- `trivy`
- `falco`
- `suricata`
- `zeek`

### sandbox profile

- `cuckoo`
- `cuckoo-web`

### bootstrap profile

- helper/bootstrap jobs such as optional model pulls.

---

## 4. Runtime Launch Modes

### Minimal API/UI mode

```bash
docker compose up -d mongodb backend frontend
```

Use this only when you understand that Celery-backed and optional integration flows may be disabled or degraded.

### Compose default mode

```bash
docker compose up -d
```

Starts the configured default stack, including Redis/Celery and the default optional services.

### Extended security mode

```bash
docker compose --profile security up -d
```

### Sandbox mode

```bash
docker compose --profile sandbox up -d
```

---

## 5. API Routing Contract

- Backend health: `GET http://localhost:8001/api/health`
- Backend API root: `GET http://localhost:8001/api/`
- Frontend local URL: `http://localhost:3000`
- Websockets: `/ws/threats` and `/ws/agent/{agent_id}`
- Most routers are mounted with an outer `/api` prefix in `backend/server.py`.
- Some routers already define `/api/v1/...` and are included directly, including CSPM and identity.
- Frontend pages should prefer same-origin `/api` behind a reverse proxy or a configured backend base URL in local development.

---

## 6. Health Validation Sequence

```bash
docker compose ps
curl -fsS http://localhost:8001/api/health
curl -fsS http://localhost:3000
```

Important: `/api/health` is a shallow health signal. It does not deeply validate every database operation or optional integration. For release confidence, validate the specific feature routes, background services, and external integrations you plan to use.

---

## 7. Current Frontend Navigation Contract

- `/` redirects to `/command` for authenticated users.
- `/dashboard`, `/alerts`, and `/threats` redirect into the command workspace tabs.
- `/email-protection` and `/email-gateway` redirect into `/email-security?tab=...`.
- `/mobile-security` and `/mdm` redirect into `/endpoint-mobility?tab=...`.
- `/agents`, `/agent-commands`, and `/swarm` redirect into `/unified-agent`.
- `/threat-intel`, `/correlation`, and `/attack-paths` redirect into the investigation workspace.
- `/quarantine`, `/response`, `/edr`, and `/soar` redirect into response operations.

Standalone page components still exist for many domains, but the route contract is workspace-oriented.

---

## 8. Acceptance Criteria for "Working"

The system is considered working when:

1. Core services are running and `GET /api/health` returns successfully.
2. Login or initial admin setup works.
3. `/command` loads and can retrieve core dashboard/alerts/threat data.
4. At least one route each from unified agent, investigation, response operations, settings, and reports loads without fatal UI errors.
5. Optional integrations fail gracefully with visible status and no cascading core failure.
6. Deployment or remediation success states represent verified execution, not a simulation-only completion state.

---

## 9. Known Contract Risks to Monitor

- Mixed `/api` and `/api/v1` route strategy.
- Optional routers registered through fail-open imports.
- Health endpoint is not a deep dependency probe.
- Workspace redirects can make old route documentation stale.
- Production email gateway requires SMTP/MTA wiring.
- MDM connectors require live credentials and provider API permissions.
- Some stateful domain managers keep in-memory queues or caches that need durability review for scaled deployments.
