# Seraph Implementation Roadmap (Code-First Refresh)

Date: 2026-04-23  
Scope: roadmap grounded in currently implemented repository logic

---

## 1) Program intent

Convert a broad, already-implemented platform into a consistently operated, contract-stable, enterprise-grade system without losing feature velocity in core domains.

---

## 2) Present-state baseline

This roadmap starts from a high implementation baseline:

- Backend routers: **62 modules / 697 handlers**
- Registered routers in runtime app: **65**
- Frontend pages: **69**
- Frontend route paths in shell app: **66**
- Unified control-plane router is a high-volume hub (agent lifecycle, command flow, EDM governance, deployment, monitors)

Evidence:
- `backend/server.py`
- `backend/routers/*.py`
- `frontend/src/App.js`
- `backend/routers/unified_agent.py`

---

## 3) Roadmap streams

### Stream A: contract discipline and compatibility
Focus:
- lock API request/response contracts for key workspace pages and high-impact routes
- reduce legacy redirect/alias drift in frontend routing
- formalize script/installer endpoint compatibility matrix

Primary components:
- `frontend/src/App.js`
- key routers: `unified_agent.py`, `cspm.py`, `email_protection.py`, `mdm_connectors.py`, `mobile_security.py`

### Stream B: governance execution determinism
Focus:
- ensure high-impact paths always flow through outbound gate and approved decision execution
- standardize decision/execution observability and denial behavior

Primary components:
- `backend/services/outbound_gate.py`
- `backend/services/governed_dispatch.py`
- `backend/services/governance_executor.py`
- `backend/services/governance_authority.py`

### Stream C: state durability normalization
Focus:
- finish applying state-version + transition-log mutation pattern to remaining mutable collections
- remove state mutation ambiguity under concurrent updates

Primary components:
- already strong: `cspm.py`, `unified_agent.py`, deployment/task models
- to expand: additional response/operational state paths

### Stream D: optional integration reliability model
Focus:
- make optional dependency behavior explicit and testable (Ollama, Falco/Suricata/Zeek, Cuckoo, etc.)
- tighten degraded-mode contracts so UI and API semantics stay deterministic

Primary components:
- `docker-compose.yml`
- `backend/services/*` and integration routers

### Stream E: operator experience consolidation
Focus:
- maintain new workspace-oriented UX while reducing duplicated legacy routes/pages
- map navigation to canonical workspace tabs and keep redirects intentional

Primary components:
- `frontend/src/App.js`
- workspace pages (`CommandWorkspacePage`, `AIActivityWorkspacePage`, `InvestigationWorkspacePage`, etc.)

---

## 4) Priority backlog (implementation-level)

1. **Contract lock for high-impact routes**
   - generate and maintain canonical contract fixtures for:
     - unified agent command/request/result routes
     - governance decision/execution routes
     - CSPM scan/finding transition routes
     - email/mobile/MDM control routes

2. **Governance pipeline invariants**
   - enforce that high-impact command types cannot bypass triune queue
   - add targeted regression tests for queue -> decision -> execution transitions and failure states

3. **Durability pattern propagation**
   - apply state-version + transition-log patterns to remaining mutable operational entities not yet covered

4. **Integration mode matrix**
   - document and test behavior for each optional integration in states:
     - available
     - degraded
     - unavailable

5. **Frontend route cleanup pass**
   - keep workspace redirects, remove stale aliases that no longer provide value
   - ensure page-level API clients align to canonical route contracts

---

## 5) Exit criteria by stream

### Stream A complete when:
- no unresolved contract drift on top workflow routes
- documented compatibility matrix is current and test-backed

### Stream B complete when:
- every high-impact action has queue + decision + execution traceability
- denial/execution outcomes are visible and auditable

### Stream C complete when:
- mutable critical entities use conflict-safe transition semantics
- concurrent-update behavior is deterministic

### Stream D complete when:
- degraded behavior for optional integrations is consistent across UI/API
- operational docs clearly separate required and optional planes

### Stream E complete when:
- workspace navigation is canonical and minimally redundant
- operator journey is stable for command, detection, investigation, and response workspaces

---

## 6) Strategic outcome

If executed, the platform keeps its major advantage (breadth + composability) while reducing enterprise adoption friction caused by contract drift, operational inconsistency, and optional dependency ambiguity.
