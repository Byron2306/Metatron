# Metatron Run-Mode Contract

Generated: 2026-04-27

## Goal

Define which services are required, optional, profile-gated, or credential-dependent so operators can run the platform predictably and understand degraded states.

## 1. Required baseline

Baseline platform operation requires:

- `mongodb`
- `redis`
- `backend`
- `frontend`

MongoDB stores platform state. Redis backs the Celery broker/result path used by async and scheduled workers. Backend exposes FastAPI routes on port `8001` in Docker. Frontend serves the React application on port `3000` or through Nginx.

## 2. Worker plane

The Compose file includes:

- `celery-worker`
- `celery-beat`

These should be enabled for asynchronous jobs, recurring validation, and worker-backed features. The dashboard can render without them, but worker-dependent flows should be treated as degraded if they are down.

## 3. Default optional integrations

These services are useful for full local operation but should not be required for baseline UI/API health:

- `elasticsearch`
- `kibana`
- `ollama`
- `wireguard`
- `nginx`

Expected behavior:

- UI remains usable if optional services are down.
- Dependent pages report unavailable/degraded state rather than breaking core SOC workflows.
- Local AI features fall back to heuristic/rule paths where available.

## 4. Profile-gated integrations

### `security` profile

- `trivy`
- `falco`
- `suricata`
- `zeek`
- `volatility`

These provide container scanning, runtime security, IDS/NDR logs, osquery-style fleet evidence, and memory forensics helper tooling. They require host permissions and may be platform-sensitive.

### `sandbox` profile

- `cuckoo`
- `cuckoo-web`
- `cuckoo-mongo`

Sandbox mode is lab-sensitive. Cuckoo requires VM/lab tuning and uses a separate MongoDB version from the main application.

### `bootstrap` profile

- `admin-bootstrap`
- `ollama-pull`

Bootstrap helpers are one-shot convenience jobs and are not runtime requirements.

## 5. Launch modes

### Minimal core

```bash
docker compose up -d mongodb redis backend frontend
```

### Full local operations

```bash
docker compose up -d mongodb redis backend celery-worker celery-beat frontend elasticsearch kibana ollama wireguard nginx
```

### Security sensor mode

```bash
docker compose --profile security up -d
```

### Sandbox mode

```bash
docker compose --profile sandbox up -d
```

### Bootstrap helpers

```bash
docker compose --profile bootstrap up admin-bootstrap ollama-pull
```

## 6. Routing contract

- Frontend uses React Router protected routes.
- Root route redirects to `/command`.
- Many legacy feature URLs redirect to workspace tabs:
  - `/alerts` and `/threats` -> `/command`
  - `/email-protection` and `/email-gateway` -> `/email-security`
  - `/mobile-security` and `/mdm` -> `/endpoint-mobility`
  - `/soar`, `/edr`, `/response`, `/quarantine` -> `/response-operations`
  - `/sigma`, `/atomic-validation`, `/mitre-attack` -> `/detection-engineering`
- Backend routers are mounted under `/api/*` plus selected native `/api/v1/*` routers.
- WebSockets are exposed at `/ws/threats` and `/ws/agent/{agent_id}`.

## 7. Health validation sequence

1. `docker compose ps`
2. `curl -fsS http://localhost:8001/api/health`
3. `curl -fsS http://localhost:3000`
4. `python3 smoke_test.py`
5. Validate optional services only if enabled.

## 8. Credential-dependent features

The following are implemented but only production-real when configured:

- SMTP relay/gateway: requires MTA routing, TLS, and mail delivery configuration.
- MDM connectors: require Intune/JAMF/Workspace ONE/Google Workspace credentials and API scopes.
- CSPM: requires cloud credentials and target account/project/subscription access.
- SIEM forwarding: requires Elasticsearch/Splunk/Syslog or provider credentials.
- Notifications: Slack, SendGrid, Twilio, SMTP require valid secrets.
- Remote deployment: SSH/WinRM requires network reachability and valid endpoint credentials.

## 9. Acceptance criteria for "working"

System is considered operational when:

1. Required baseline services are healthy.
2. Login/setup works and the protected React shell renders.
3. Core SOC read paths work: command dashboard, threats/alerts data, timeline/audit or investigation views, unified agent status.
4. Optional pages clearly degrade when dependencies or credentials are absent.
5. Deployment and high-risk action success states correspond to verified execution evidence, or explicitly mark simulated/test behavior.

## 10. Current risk focus

- Keep API/client contracts aligned as workspace pages and route redirects evolve.
- Avoid ambiguous success states in deployment, connector, and action-execution paths.
- Persist governance-critical state consistently across restarts and scaled services.
- Maintain explicit optional-dependency status for security sensors, MDM, SMTP, CSPM, and AI/LLM paths.
