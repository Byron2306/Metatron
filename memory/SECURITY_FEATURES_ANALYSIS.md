# Metatron Security Features Analysis (Code-Evidence Refresh)

Generated: 2026-04-23  
Scope: implemented security controls validated from current repository code.

---

## 1) Executive summary

The current codebase implements a broad security surface across:

- endpoint agent telemetry and local monitors,
- centralized backend orchestration and response,
- governance-gated high-impact execution,
- email and mobile/MDM protection domains,
- cloud posture management with durable transitions.

The major remaining risks are less about missing modules and more about runtime consistency, integration readiness, and operational discipline in production.

---

## 2) Evidence baseline

Primary anchor files:

- `backend/server.py`
- `backend/routers/*.py` (62 modules, 697 route handlers)
- `backend/services/{outbound_gate,governed_dispatch,governance_executor,identity,policy_engine,token_broker,tool_gateway,telemetry_chain}.py`
- `backend/routers/{unified_agent,cspm,email_protection,email_gateway,mobile_security,mdm_connectors}.py`
- `unified_agent/core/agent.py`

---

## 3) Implemented capability inventory

### 3.1 Access control and identity plane

**Status: IMPLEMENTED**

What is present:

- JWT token auth and role-based permissions (`read`, `write`, `delete`, `manage_users`, etc.).
- Production/strict-mode JWT secret validation and weak-secret rejection paths.
- Remote-admin gating for non-local requests.
- Machine token checks for service-to-service and websocket authentication.
- Setup-token protected bootstrap for initial admin creation.

Evidence:

- `backend/routers/dependencies.py`
- `backend/routers/auth.py`

---

### 3.2 Endpoint control plane and telemetry ingestion

**Status: IMPLEMENTED**

What is present:

- Agent registration, heartbeat, command polling, command result ingestion.
- Command durability/state transitions in Mongo-backed collections.
- Fleet posture and monitor telemetry summaries.
- Download/install script endpoints for Linux/Windows/macOS/mobile patterns.

Evidence:

- `backend/routers/unified_agent.py`
- `unified_agent/core/agent.py`

---

### 3.3 Endpoint monitor depth (agent-side)

**Status: IMPLEMENTED (broad)**

Key monitor families in `unified_agent/core/agent.py` include:

- process/network/registry/process-tree and LOLBin detection,
- DNS, memory, AMSI, firewall, ransomware, YARA,
- rootkit and kernel security monitors,
- DLP + EDM monitor paths,
- email protection and mobile security local monitors,
- identity/privilege/alias/CLI telemetry and auto-throttle monitors.

The module currently defines **21 `*Monitor` classes** and additional detector classes.

---

### 3.4 Governance-gated action execution

**Status: IMPLEMENTED**

What is present:

- Central outbound gate queues high-impact actions and forces triune approval for mandatory action classes.
- Governed dispatch persists command metadata with authority and decision context.
- Governance executor consumes approved decisions and executes domain operations.
- Governance authority supports explicit approve/deny transitions and queue syncing.

Evidence:

- `backend/services/outbound_gate.py`
- `backend/services/governed_dispatch.py`
- `backend/services/governance_executor.py`
- `backend/services/governance_authority.py`

---

### 3.5 Token/policy/tool control substrate

**Status: IMPLEMENTED**

What is present:

- Policy decision engine with approval tiers (`AUTO`, `SUGGEST`, `REQUIRE_APPROVAL`, `TWO_PERSON`).
- Scoped capability token model and governance-aware admin token operations.
- Tool gateway and constrained command execution logic.
- Trace/audit fields attached to decision and token flows.

Evidence:

- `backend/services/policy_engine.py`
- `backend/services/token_broker.py`
- `backend/services/tool_gateway.py`

---

### 3.6 Tamper-evident telemetry chain

**Status: IMPLEMENTED**

What is present:

- hash-chained signed event envelopes,
- action audit records with trace IDs and governance metadata,
- integrity verification and trace-span lifecycle helpers.

Evidence:

- `backend/services/telemetry_chain.py`

---

### 3.7 Cloud Security Posture Management (CSPM)

**Status: IMPLEMENTED**

What is present:

- provider config API (governed for high-impact operations),
- scan start/list/detail workflows,
- finding/resource listing and filtering,
- finding status transitions with optimistic-concurrency style safeguards,
- compliance reports, exports, dashboard and stats,
- demo seed mode when no providers are configured.

Evidence:

- `backend/routers/cspm.py`
- `backend/cspm_engine.py`

---

### 3.8 Email security (protection + gateway)

**Status: IMPLEMENTED**

What is present:

- Email protection APIs: analyze, URL/attachment analysis, SPF/DKIM/DMARC checks, DLP checks, quarantine workflows, protected-user and sender/domain list management.
- Email gateway APIs: process message, stats, quarantine release/delete, blocklist/allowlist, policy retrieval/update.

Evidence:

- `backend/routers/email_protection.py`
- `backend/routers/email_gateway.py`
- `backend/email_protection.py`
- `backend/email_gateway.py`

---

### 3.9 Mobile security + MDM connectors

**Status: IMPLEMENTED**

What is present:

- Mobile security API: device registration/lifecycle, posture updates, app analysis, compliance and threat reporting.
- MDM API: connector lifecycle, connect/disconnect/all-connect, sync, device actions (lock/wipe/retire/sync), policy/platform views.

Evidence:

- `backend/routers/mobile_security.py`
- `backend/routers/mdm_connectors.py`
- `backend/mobile_security.py`
- `backend/mdm_connectors.py`

---

## 4) Deployment/runtime security posture

`docker-compose.yml` enforces a practical split between:

- core services (backend/frontend/mongodb/redis),
- local SIEM/LLM support (Elasticsearch/Kibana/Ollama),
- profile-gated security tooling (Trivy/Falco/Suricata/Zeek/Volatility),
- profile-gated sandbox stack (Cuckoo components),
- optional bootstrap helpers.

This supports multi-mode operation but means some feature depth remains environment-dependent.

---

## 5) Residual gaps and risk notes

1. **Operational consistency:** centralized composition in `server.py` increases startup coupling and maintenance risk.
2. **Integration readiness:** several advanced controls depend on external services/credentials.
3. **Advanced isolation depth:** browser/sandbox capabilities are meaningful but still mixed between core and optional modes.
4. **Documentation drift risk:** legacy narratives can quickly diverge from active route and service behavior if not refreshed continuously.

---

## 6) Bottom line

Security capability coverage is materially broad and code-real across endpoint, governance, cloud posture, email, and mobile domains.  
Near-term maturity gains should come from **tightening operational guarantees and consistency**, not from adding entirely new control families.
