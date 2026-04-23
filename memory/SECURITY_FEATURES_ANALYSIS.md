# Metatron / Seraph Security Features Analysis (Code-Evidenced)

**Last updated:** 2026-04-23  
**Classification:** Repository-backed capability map  
**Primary evidence:** `backend/server.py`, `backend/routers/dependencies.py`, `backend/routers/unified_agent.py`, `backend/services/outbound_gate.py`, `backend/services/governed_dispatch.py`, `backend/routers/integrations.py`, `backend/integrations_manager.py`, `backend/routers/world_ingest.py`, `backend/services/telemetry_chain.py`, `unified_agent/core/agent.py`

---

## 1) Executive Summary

Security capability breadth is strong across endpoint monitoring, API-level governance, machine-token ingest/auth, and governed command dispatch.  
The most important quality of the current implementation is that high-impact operations are explicitly gated through triune queue/decision paths instead of direct execution.

Current gaps are less about missing feature classes and more about operational consistency:

- aligning all auxiliary/legacy entry points to the same hardening defaults,
- reducing environment drift between scripts and runtime defaults,
- and expanding negative-path testing for auth/governance controls.

---

## 2) Identity, Auth, and Access Controls

### 2.1 User authentication and role model

Implemented in `backend/routers/auth.py` and `backend/routers/dependencies.py`:

- JWT bearer auth (`HS256`) with 24-hour expiration.
- Strong-secret enforcement in production/strict mode (`JWT_SECRET` checks).
- First-user/first-admin bootstrap semantics and one-time `/auth/setup`.
- Role/permission model:
  - `admin`: read/write/delete/manage users
  - `analyst`: read/write
  - `viewer`: read

### 2.2 Remote admin constraint

`get_current_user()` enforces remote admin restrictions when `REMOTE_ADMIN_ONLY=true`:

- non-local requests must be admin, or
- must match allowed addresses via `REMOTE_ADMIN_EMAILS`.

This is a meaningful hardening control for exposed deployments.

### 2.3 Machine token authorization channels

Machine-token helpers in dependencies support:

- optional token auth (for dual user/machine endpoints),
- required token auth (for ingest/internal channels),
- websocket token auth.

Used by integrations and world ingest routes to protect automation pathways.

---

## 3) Agent Security Model

### 3.1 Agent enrollment and auth

`backend/routers/unified_agent.py`:

- Enrollment key support (`X-Enrollment-Key`),
- signed token model using `SERAPH_AGENT_SECRET`,
- explicit development fallback secret with warning.

`unified_agent/core/agent.py` registers against:

- `POST /api/unified/agents/register`
- heartbeat, command polling, and command-result endpoints under `/api/unified/agents/*`.

### 3.2 Trusted-network fallback

Router includes `UNIFIED_AGENT_ALLOW_TRUSTED_NETWORK_AUTH` behavior.  
This is powerful but should remain disabled except in controlled environments, since it weakens strict token-only guarantees.

### 3.3 Endpoint monitor coverage

The monolithic unified agent includes broad endpoint monitor classes including:

- process/network/registry/LOLBin/code-signing/DNS,
- DLP/EDM/memory/vulnerability/YARA,
- ransomware/rootkit/kernel/self-protection/identity,
- CLI telemetry, privilege escalation, hidden file, email protection, and mobile security monitors.

This gives extensive signal collection; value depends on tuning and governance.

---

## 4) Governance and High-Impact Action Controls

### 4.1 Mandatory outbound gate

`backend/services/outbound_gate.py` defines mandatory high-impact action classes:

- `agent_command`, `swarm_command`,
- `response_*`, quarantine actions,
- tool execution classes including `mcp_tool_execution`.

For these actions:

- triune approval cannot be skipped,
- impact cannot be downgraded below high.

### 4.2 Queue/decision persistence model

`gate_action()` writes to:

- `triune_outbound_queue`
- `triune_decisions`

and emits `outbound_gate_action_queued` world events.

### 4.3 Governed dispatch for agent commands

`backend/services/governed_dispatch.py`:

- stamps command metadata with queue/decision IDs,
- persists `gated_pending_approval`,
- creates transition logs and decision context,
- and emits delivery events.

This is a core security strength: command execution is mediated, auditable, and stateful.

---

## 5) Integrations and Runtime Tool Security

### 5.1 Tool allowlist

`backend/integrations_manager.py` exposes `SUPPORTED_RUNTIME_TOOLS` allowlist:

- amass, arkime, bloodhound, spiderfoot, velociraptor, purplesharp,
- sigma, atomic, falco, yara, suricata, trivy, cuckoo, osquery, zeek.

Unsupported tools are rejected.

### 5.2 Runtime target control

`run_runtime_tool()` supports:

- `runtime_target=server` (server execution), and
- unified-agent runtime target paths (queued through governance).

### 5.3 Integrations auth model

`backend/routers/integrations.py` supports:

- user auth + role permissions for interactive operations,
- optional machine-token auth (`INTEGRATION_API_KEY`, `SWARM_AGENT_TOKEN`) for internal automation.

Production backend startup requires `INTEGRATION_API_KEY`, preventing accidental open internal channels.

---

## 6) World Ingest and Machine Ingress Security

`backend/routers/world_ingest.py`:

- machine-token required for `/api/ingest/*`,
- supports ingest for entities, edges, detections, alerts, policy violations, and token events,
- emits world events and can trigger risk recalculation.

This path is security-sensitive and correctly requires dedicated machine auth.

---

## 7) Auditability and Tamper Evidence

`backend/services/telemetry_chain.py` provides tamper-evident telemetry structures used in governance and unified-agent audit flows.  
`_record_unified_audit()` in unified-agent router records controlled actions through telemetry chain hooks.

This supports stronger forensic traceability for sensitive operations.

---

## 8) Email, Mobile, and MDM Security Surfaces

### Email Gateway

`backend/routers/email_gateway.py` and service layer:

- processing endpoint,
- quarantine release/delete workflows,
- blocklist/allowlist management,
- policy retrieval/update.

Write operations are permission-gated (`check_permission("write")` / `"admin"` where applicable).

### MDM connectors

`backend/routers/mdm_connectors.py`:

- admin-gated connector management,
- write/admin checks for remote actions (lock/wipe/etc.),
- platform inventory/policy endpoints.

### Mobile and endpoint side

Unified agent includes `EmailProtectionMonitor` and `MobileSecurityMonitor`, contributing endpoint-level signals tied into broader telemetry.

---

## 9) Security Maturity Snapshot (Evidence-Scoped)

| Security Domain | Current State | Evidence Confidence |
|---|---|---|
| User auth + JWT controls | Strong, production-aware | High |
| Role/permission checks | Broadly implemented | High |
| Remote admin gating | Implemented and enabled by default in compose | High |
| Agent auth + enrollment | Implemented with env-driven hardening | High |
| High-impact action governance | Strong queue/decision gating model | High |
| Integrations runtime allowlisting | Implemented | High |
| Machine-token ingestion paths | Implemented | High |
| Tamper-evident telemetry | Implemented with audit hooks | Medium-High |
| Optional service fail-closed behavior | Partial, service-dependent | Medium |
| Legacy/auxiliary surface hardening parity | Incomplete | Medium-Low |

---

## 10) Top Residual Risks

1. **Hardening parity across auxiliary components**
   - Some secondary/legacy services still use weaker defaults than main backend.

2. **Configuration drift**
   - Script and environment defaults can diverge from canonical deployment expectations.

3. **Trusted network auth misuse risk**
   - If enabled broadly, could weaken strict token-based controls.

4. **Assurance depth**
   - More systematic denial-path tests are needed for auth, machine-token, and governance transitions.

---

## 11) Recommended Next Security Work

1. Normalize strict security mode behavior across all entry points and helper APIs.
2. Add automated regression tests for:
   - missing/invalid machine tokens,
   - governance queue state transitions,
   - blocked high-impact direct execution attempts.
3. Standardize deployment script defaults to avoid accidental open/dev settings.
4. Expand telemetry-chain verification workflows for forensic integrity validation.

---

## 12) Bottom Line

The platform has a materially strong security control plane in its primary backend: explicit auth/role checks, machine-token ingress protection, and mandatory governance for impactful operations.  
The remaining work is chiefly about hardening consistency and assurance rigor, not absence of major security feature domains.
