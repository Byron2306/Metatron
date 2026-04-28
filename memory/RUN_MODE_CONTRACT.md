# Metatron Run-Mode Contract (Source of Truth)

Updated: 2026-04-28
Source basis: direct repository review of `backend/server.py`, `docker-compose.yml`, `frontend/src/App.js`, `frontend/src/lib/api.js`, and integration code.

## Goal

Define the required and optional runtime components so operators can bring up the platform predictably and understand degraded behavior.

## Required core services

A baseline dashboard/API run requires:

- `mongodb`
- `backend` (`backend.server:app`, port 8001)
- `frontend` (React/Craco, port 3000)

`redis` is required for Celery-backed/background workflows and is included in the current Compose dependency graph for the backend and worker services.

The core stack is healthy only when the backend `/api/health` endpoint responds and the frontend can load and authenticate against the backend API.

## Default optional integrations

These should degrade gracefully if unavailable:

- `wireguard`
- `elasticsearch`
- `kibana`
- `ollama`
- `celery-worker` / `celery-beat` for workflows that are not using async jobs
- external SIEM, SMTP, SendGrid, Twilio, Slack, cloud-provider, MDM, and identity-provider credentials

Behavior contract:

- The UI remains usable when optional services are down.
- Feature pages show degraded, unavailable, or credential-required states instead of reporting completed work.
- Backend jobs that cannot run due to missing tools or targets should fail explicitly with actionable reason fields.

## Profile/tool-dependent integrations

Runtime security tooling is conditional on installed binaries, containers, logs, privileges, or profile selection. Examples from `backend/integrations_manager.py` and compose/scripts include:

- `trivy`
- `falco`
- `suricata`
- `cuckoo`
- `osquery`
- `zeek`
- `yara`
- `amass`
- `arkime`
- `bloodhound`
- `spiderfoot`
- `velociraptor`
- `purplesharp`
- `atomic`
- `sigma`

## Runtime launch modes

### Minimal local core

```bash
docker compose up -d mongodb redis backend frontend
```

### Recommended local operator mode

```bash
docker compose up -d mongodb redis backend frontend celery-worker celery-beat elasticsearch kibana ollama wireguard
```

### Security-tool mode

Use the compose profiles and services configured in `docker-compose.yml` for scanner/sensor-heavy workflows. Validate host privileges before expecting kernel, VPN, packet, or sandbox features to work.

## API routing contract

- The backend binds to port 8001 in Docker Compose.
- The frontend binds to port 3000 in Docker Compose.
- Frontend API base is resolved in `frontend/src/lib/api.js` from `REACT_APP_BACKEND_URL`; same-origin `/api` is preferred behind a reverse proxy.
- Most backend routers are mounted under `/api` from `backend/server.py`.
- Some routers retain native `/api/v1` prefixes and are mounted without an extra prefix, including CSPM, identity, attack paths, secure boot, and kernel sensors.
- Deception is mounted under both `/api/deception` and `/api/v1/deception` for compatibility.
- Raw WebSockets exist at `/ws/threats` and `/ws/agent/{agent_id}`; router-level websocket paths may also exist under their mounted prefixes.

## Health validation sequence

1. Check container state:

   ```bash
   docker compose ps
   ```

2. Check backend health:

   ```bash
   curl -fsS http://localhost:8001/api/health
   ```

3. Check frontend availability:

   ```bash
   curl -fsS http://localhost:3000
   ```

4. For API route breadth, use targeted pytest suites or validation scripts that match current routes. Do not treat `python3 smoke_test.py` as the canonical smoke check; the root `smoke_test.py` is a standalone FastAPI-style app, not a simple route probe.

## "Working" interpretation

The system is working in a given run mode when:

1. Required core services are healthy.
2. Authentication/login and the default command workspace load.
3. Core SOC read paths for threats, alerts, timeline, reports, settings, and unified agent respond without fatal errors.
4. Optional integrations clearly report connected, degraded, unavailable, or credential-required states.
5. Deployment and high-impact action success states correspond to verified execution evidence, not just queue acceptance.
6. High-impact commands are gated through governance and leave audit/world-event evidence.

## Known drift risks to monitor

- Route and schema drift between backend routers, frontend workspaces, unified-agent clients, and scripts.
- Legacy path references involving `server_old.py`, `/api/agent/*`, and older validation probes.
- Default URL drift among `localhost:8001`, reverse-proxied `/api`, and historical cloud IP defaults.
- Optional integration jobs that are unavailable due to missing binaries, logs, containers, credentials, or live agents.
- Documentation claims that do not name the exact run mode and validation artifact.
