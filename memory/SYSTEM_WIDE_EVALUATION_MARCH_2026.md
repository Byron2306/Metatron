# Metatron / Seraph System-Wide Evaluation (Code-Validated Snapshot)

**Last updated:** 2026-04-23  
**Scope:** architecture, runtime operations, security/governance, and major feature surfaces based on current repository code.

---

## 1) Executive Summary

The platform is a broad, integrated security stack centered on:

- FastAPI backend (`backend/server.py`) mounted under `/api`
- React frontend (`frontend/`)
- unified endpoint agent with a large monolithic runtime (`unified_agent/core/agent.py`)
- governance-gated high-impact action dispatch (`backend/services/outbound_gate.py`, `governed_dispatch.py`)
- optional SIEM/sandbox/sensor services via Docker Compose profiles.

The codebase demonstrates high feature breadth with explicit security constraints (production boot guards, machine-token channels, remote-admin gating) and active governance workflows for command execution.

---

## 2) Runtime and Deployment Evaluation

### 2.1 Core runtime

Primary Compose services that represent the practical stack:

- `mongodb`
- `redis`
- `backend`
- `frontend`

Primary API health path:

- `GET /api/health` on backend port 8001.

### 2.2 Optional/extended runtime

Compose provides optional/extended services for:

- SIEM/analytics: Elasticsearch + Kibana
- local model support: Ollama
- VPN: WireGuard
- security profile: Trivy/Falco/Suricata/Zeek/Volatility
- sandbox profile: Cuckoo + dedicated Mongo 5.

### 2.3 Production override behavior

`docker-compose.prod.yml` enforces production posture by:

- hiding direct backend/frontend host ports,
- making Nginx ingress-centric,
- enabling production/strict backend security environment flags,
- promoting profile-gated security services into active stack entries.

---

## 3) API and Control Plane Evaluation

### 3.1 Backend route model

`backend/server.py` wires many routers under `/api`, plus websocket endpoints (`/ws/threats`, `/ws/agent/{agent_id}`) with machine-token verification.

Key behavior:

- production requires `INTEGRATION_API_KEY` at startup,
- CORS policy in strict/production rejects wildcard origins,
- optional enterprise routers fail-open if unavailable (logged warning), reducing startup brittleness.

### 3.2 Background workers started by API startup

From backend startup lifecycle:

- CCE worker start
- network discovery start
- agent deployment service start
- AATL and AATR initialization
- integrations scheduler trigger
- governance executor trigger
- Falco-to-alert persistence callback when Falco is available.

This is materially beyond a request/response API and should be treated as a background-processing control plane.

### 3.3 Unified-agent control contract

Canonical agent contract is under:

- `/api/unified/agents/register`
- `/api/unified/agents/{agent_id}/heartbeat`
- `/api/unified/agents/{agent_id}/commands`
- `/api/unified/agents/{agent_id}/command-result`

The monolithic agent implementation in `unified_agent/core/agent.py` follows this contract directly.

---

## 4) Security and Governance Evaluation

### 4.1 Authentication and access controls

Current implementation includes:

- JWT auth with strict secret requirements in production/strict mode (`routers/dependencies.py`)
- role/permission checks (`admin`, `analyst`, `viewer`)
- remote-admin gate (`REMOTE_ADMIN_ONLY`, `REMOTE_ADMIN_EMAILS`)
- machine-token dependencies for ingestion, integrations, and websocket channels.

### 4.2 Agent authentication posture

Unified-agent router uses:

- enrollment and signed token checks (`SERAPH_AGENT_SECRET`)
- optional trusted-network auth path controlled by `UNIFIED_AGENT_ALLOW_TRUSTED_NETWORK_AUTH`.

Default development secret fallback exists and should be overridden in real deployments.

### 4.3 Governance gate strength

`OutboundGateService` enforces a mandatory-high-impact action list (e.g., `agent_command`, `swarm_command`, `response_*`, `mcp_tool_execution`) and prevents low-impact downgrades for those paths.

`GovernedDispatchService` then writes gated command records with queue/decision metadata and transitions to execution pipelines.

### 4.4 Tamper-evident telemetry integration

Unified-agent router integrates tamper-evident action recording (`services/telemetry_chain.py`) for audited control-plane actions.

---

## 5) Feature Surface Evaluation

### 5.1 Email and mobile domains

Repository includes active backend/router/UI implementations for:

- email protection
- email gateway
- mobile security
- MDM connectors.

These are not placeholders; they have service logic and API surfaces wired in `server.py`.

### 5.2 Integrations runtime model

Integrations support:

- server-side tool execution (`runtime_target=server`)
- unified-agent runtime queueing (`runtime_target=unified_agent*`) via governance-gated commands
- shared allowlist via `SUPPORTED_RUNTIME_TOOLS`.

This gives a clear dual-execution model (server vs endpoint agent).

### 5.3 Cognition and scoring paths

Cognition stack is split:

- CCE worker/session summaries for command-stream behavior
- cognition fabric fused scoring for cognitive pressure and policy-tier recommendation
- separate threat correlation engine for IOC/intel/campaign-style enrichment.

---

## 6) Reliability and Drift Risks

### 6.1 Current strengths

- broad modular route/service layout
- explicit production security guardrails
- governed high-impact action queue
- practical compose profiles for optional capabilities.

### 6.2 Primary residual risks

1. **Frontend API base inconsistencies across pages** can still create environment-specific drift.
2. **Multiple agent surfaces** (monolithic agent vs desktop/UI helper APIs) can confuse contract ownership.
3. **Legacy/auxiliary services** (for example `unified_agent/server_api.py`) can be mistaken for primary control plane.
4. **Script default URL assumptions** may target stale hosts unless explicitly overridden.

---

## 7) Updated Conclusion

The platform is currently best described as:

- **feature-rich and operationally broad**, with
- **real governance and security controls in the core paths**, and
- **remaining risk concentrated in contract consistency and deployment hygiene**, not missing major subsystems.

For ongoing maturity, the highest-value path is continued contract normalization (frontend/API/agent), stricter environment validation, and expanded regression coverage around security-sensitive flows.
