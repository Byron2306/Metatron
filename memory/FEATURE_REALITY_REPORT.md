# Feature Reality Report (Code-Evidenced)

**Last updated:** 2026-04-23  
**Scope:** Qualitative implementation narrative tied to current repository logic

---

## Executive summary

The platform is broad and materially implemented across endpoint, network, response, integrations, email, mobile, MDM, and governance control planes.  
The current risk profile is not "missing core capability"; it is mostly about:

1. runtime/deployment consistency,
2. contract drift across multiple agent/UI surfaces,
3. production credentialization for external systems.

---

## 1) Platform reality by domain

### 1.1 Backend API core

**What is real now**
- Main API app is `backend/server.py` (`FastAPI`).
- Primary HTTP base is `/api/*` with many routers mounted under that prefix.
- Health endpoint is `GET /api/health`.
- App startup wires database handles into many subsystems (timeline, intel, response, zero trust, CSPM, world model, triune services, ML predictor).

**Operational behavior**
- In production, missing `INTEGRATION_API_KEY` raises startup error.
- CORS in production/strict mode requires explicit origins and rejects wildcard.
- Startup launches background services: CCE worker, network discovery, deployment service, AATL, AATR, integrations scheduler, governance executor (with error logging if optional startup steps fail).

---

### 1.2 Unified agent reality (important distinction)

**Monolithic endpoint agent (`unified_agent/core/agent.py`)**
- Registers to `POST /api/unified/agents/register`.
- Heartbeats to `/api/unified/agents/{agent_id}/heartbeat`.
- Polls commands from `/api/unified/agents/{agent_id}/commands`.
- Posts command results to `/api/unified/agents/{agent_id}/command-result`.
- Contains broad monitor set (process/network/registry/LOLBin/DNS/memory/DLP/yara/ransomware/rootkit/kernel identity/email/mobile/etc.).
- Can run integration runtimes through an allowlist (`amass`, `arkime`, `bloodhound`, `spiderfoot`, `velociraptor`, `purplesharp`, `sigma`, `atomic`, `trivy`, `falco`, `suricata`, `yara`, `osquery`, `zeek`, `cuckoo`).

**Desktop/web UI helpers are separate surfaces**
- `unified_agent/ui/desktop/main.py` and `unified_agent/ui/web/app.py` are alternate local UI/core wrappers.
- `unified_agent/server_api.py` is a separate FastAPI service with in-memory stores and proxy behavior; it is not the canonical backend API.

**Why this matters**
- Documentation must not treat "the agent" as a single contract. There are at least three distinct runtime surfaces.

---

### 1.3 Integrations runtime and governance

**What is real now**
- Integrations API is in `backend/routers/integrations.py`.
- Tools can run either:
  - on server (`runtime_target=server`), or
  - on unified agent (`runtime_target=unified_agent*`) via queued command flow.
- Supported runtime tools are centrally defined in `backend/integrations_manager.py` (`SUPPORTED_RUNTIME_TOOLS`).

**Governance behavior**
- Remote/runtime dispatch to unified agents uses governed queueing (`GovernedDispatchService` + `OutboundGateService`) and Triune decision paths.
- High-impact actions are hard-enforced as triune-gated (`MANDATORY_HIGH_IMPACT_ACTIONS` includes `agent_command`, `swarm_command`, response/quarantine operations, tool execution paths).

---

### 1.4 Cognition, scoring, and fusion

**What is real now**
- CCE worker (`backend/services/cce_worker.py`) continuously analyzes `cli.command` streams, stores session summaries, and can trigger SOAR evaluation for high machine-likelihood sessions.
- Cognition fusion (`backend/services/cognition_fabric.py`) combines:
  - AATL assessments,
  - CCE session summaries,
  - ML predictions,
  - AATR matching,
  - AI-reasoning uncertainty.
- Fusion computes:
  - `cognitive_pressure`,
  - `autonomous_confidence`,
  - recommended policy tier from thresholds.

**Interpretation**
- This is a real multi-source scoring path, not just static rule labels.

---

### 1.5 Email security and gateway

**What is real now**
- `backend/email_protection.py` + `backend/routers/email_protection.py` implement post-delivery style checks (SPF/DKIM/DMARC analysis, phishing heuristics, URL and attachment analysis, impersonation, DLP patterns, quarantine logic).
- `backend/email_gateway.py` + `backend/routers/email_gateway.py` expose gateway operations:
  - stats,
  - process test payload,
  - quarantine list/release/delete,
  - blocklist/allowlist management,
  - policy reads/updates.

**Current limitation**
- Frameworks and API/control logic are present, but real enterprise SMTP deployment still depends on environment-specific infrastructure and credentials.

---

### 1.6 Mobile security and MDM connectors

**What is real now**
- `backend/mobile_security.py` + router provide device lifecycle/compliance/threat APIs.
- `backend/mdm_connectors.py` + router support connector management for:
  - Intune,
  - JAMF,
  - Workspace ONE,
  - Google Workspace.
- Includes connector CRUD, connect/disconnect, sync, device actions (lock/wipe/retire/sync), policy/platform views.

**Current limitation**
- Production-grade value requires real MDM tenant credentials and operational webhook/event integration.

---

### 1.7 Security and access control

**What is real now**
- JWT security policy in `routers/dependencies.py`:
  - weak/missing JWT secret fails in production/strict mode,
  - dev mode can fall back to ephemeral secret with warning.
- `REMOTE_ADMIN_ONLY` logic restricts remote access to admin role/allowed emails.
- Machine token flows protect websocket/internal ingest/integration channels.
- Unified-agent auth uses `SERAPH_AGENT_SECRET` and enrollment key/token model.
- Optional trusted-network auth fallback exists but is feature-flag controlled (`UNIFIED_AGENT_ALLOW_TRUSTED_NETWORK_AUTH`).

---

### 1.8 Deployment/runtime model

**What is real now**
- Compose runtime (`docker-compose.yml`) is broad and profile-driven:
  - core: mongodb, redis, backend, frontend,
  - optional/common: elasticsearch, kibana, ollama, wireguard,
  - security profile: trivy/falco/suricata/zeek/volatility,
  - sandbox profile: cuckoo stack with dedicated Mongo 5.
- Production override (`docker-compose.prod.yml`) hides internal ports and uses Nginx as ingress.
- Frontend container Nginx config proxies `/api` to backend by service name, aligning same-origin UI operation.

---

## 2) What works well today

- Core auth and API routing under `/api`.
- Unified-agent register/heartbeat/command control loop in canonical router/agent paths.
- Integration runtime model with explicit tool allowlist and queue records.
- Outbound governance gate for high-impact actions.
- Multi-domain feature breadth: EDR-style monitors, timeline/correlation, response, email/mobile/MDM surfaces.

---

## 3) What remains conditional or limited

1. **Production external-system depth**  
   SMTP and MDM frameworks need real environment credentials and operational integrations.

2. **Contract consistency across parallel surfaces**  
   Monolithic unified agent, desktop/web helper core, and legacy auxiliary API paths differ and require careful deployment alignment.

3. **Optional dependency determinism**  
   Elasticsearch/Kibana/Ollama/WireGuard/security sensors can be absent; behavior must remain graceful and consistently signaled.

4. **Script defaults and docs drift**  
   Some scripts/docs still assume legacy IPs or older health paths/ports and should be normalized.

---

## 4) Reality-driven priority actions

### Immediate
1. Keep docs and runbooks aligned to `/api` + port 8001 backend contract.
2. Clarify canonical agent contract (`/api/unified/*`) versus auxiliary agent surfaces.
3. Validate production env requirements (`JWT_SECRET`, `INTEGRATION_API_KEY`, explicit CORS origins).

### Near-term
1. Harden and test trusted-network auth fallback behavior.
2. Expand contract tests covering integrations runtime-target behavior.
3. Standardize script defaults for local/prod URLs and health checks.

### Medium-term
1. Expand durability and assurance for governance/executor state.
2. Continue reducing adapter/legacy drift across agent-facing APIs.

---

## 5) Final reality statement

The repository represents a **feature-rich, code-real security platform** with meaningful implementation across endpoint telemetry, response, governance, email, and mobile/MDM operations.  
Current maturity concerns are primarily about **operational consistency and contract integrity**, not absence of core security logic.
