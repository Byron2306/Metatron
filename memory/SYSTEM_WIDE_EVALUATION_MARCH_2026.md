# Metatron / Seraph System-Wide Evaluation (Current Code State)

**Last updated:** 2026-04-16  
**Scope:** Broad system coverage, corrected against present repository behavior

---

## 1) Executive Summary

The platform provides broad integrated security functionality across endpoint, cloud, email, mobile, and response operations. The most important updates from earlier March-era evaluations are:

1. Route and workspace wiring are now more consolidated and coherent.
2. Security controls (auth/CORS/remote admin gating) are stronger than many older docs describe.
3. Some capability claims in older docs are overstated (especially MDM connector implementation depth).

---

## 2) System Breadth Snapshot

### API and service shape

- FastAPI backend in `backend/server.py`
- **65 included routers** in current server wiring
- High-volume domain routers across:
  - unified agent control
  - cloud posture (CSPM)
  - enterprise governance/advanced services
  - email security (gateway + protection)
  - endpoint mobility (mobile security + MDM)

### Frontend shape

- React app with route consolidation in `frontend/src/App.js`
- Workspace-first navigation via:
  - `EmailSecurityWorkspacePage`
  - `EndpointMobilityWorkspacePage`
- Sidebar/nav map in `frontend/src/components/Layout.jsx`

### Runtime topology

- `docker-compose.yml` includes core + optional security/sandbox stacks:
  - core db/app/worker services
  - Elasticsearch/Kibana/Ollama
  - Trivy/Falco/Suricata/Zeek
  - Cuckoo stack
  - WireGuard and nginx

---

## 3) Domain-by-Domain Status

## 3.1 Email Security

### Email Gateway

- Service logic: `backend/email_gateway.py`
- Router: `backend/routers/email_gateway.py`
- Router handlers: **12**
- Includes:
  - process/analyze path
  - quarantine list/release/delete
  - blocklist + allowlist management
  - policy retrieval/update
  - stats

### Email Protection

- Service logic: `backend/email_protection.py`
- Router: `backend/routers/email_protection.py`
- Router handlers: **17**
- Includes:
  - full email analyze
  - URL analyze
  - attachment analyze
  - SPF/DKIM/DMARC checks
  - DLP checks
  - quarantine + list governance entities

**Evaluation:** Mature feature surface for an integrated internal platform.

---

## 3.2 Endpoint Mobility

### Mobile Security

- Service: `backend/mobile_security.py`
- Router: `backend/routers/mobile_security.py`
- Router handlers: **17**
- Includes device registration/lifecycle, status update, compliance checks, threat workflows, app analysis, policy updates.

### MDM Connectors (corrected)

- Service: `backend/mdm_connectors.py`
- Router: `backend/routers/mdm_connectors.py`
- Router handlers: **18**
- Concrete connector classes currently present:
  - `IntuneConnector`
  - `JAMFConnector`
- Connector manager instantiation path supports those two implementations.
- Platform enum values include `workspace_one` and `google_workspace`, but concrete connector classes for those are not present.

**Evaluation:** Strong framework and API coverage; implementation depth currently two-platform for concrete connectors.

---

## 3.3 Unified Agent and EDM

- Control plane router: `backend/routers/unified_agent.py` (**51 handlers**)
- Endpoint agent implementation: `unified_agent/core/agent.py`
- Unified agent initializes broad monitor coverage (process/network, registry, memory, DLP, YARA, rootkit, kernel, identity, email, mobile, etc.).
- EDM API surface includes datasets, versions, publish, rollback, telemetry summary, and rollout lifecycle endpoints.

**Evaluation:** One of the most mature domain surfaces in the codebase.

---

## 3.4 Cloud Security (CSPM)

- Router: `backend/routers/cspm.py` (**18 handlers**)
- Prefix: `/api/v1/cspm`
- High-impact operations use governance gating (`OutboundGateService`, `requires_triune=True`) on provider configure/remove and scan initiation.
- Scan endpoint requires authenticated user dependency.
- Demo-seed fallback exists for usability when no providers are configured.

**Evaluation:** Strongly structured control flow with governance hooks; enterprise operational quality depends on provider credential lifecycle and scanner coverage tuning.

---

## 3.5 Security Hardening Baseline

From `backend/routers/dependencies.py` + `backend/server.py`:

- JWT secret policy enforcement in strict/production mode.
- Strong-password secret length checks + weak-default rejection logic.
- Role-based permissions and per-route permission dependencies.
- Remote admin-only access gate for non-local requests.
- CORS origin resolution with strict protections.

**Evaluation:** Meaningful hardening controls are in place and active.

---

## 4) Corrected Gap Register (vs prior inflated claims)

1. **MDM platform support claim drift:** documentation often listed 4 implemented connector classes; current code implements 2 concrete connectors.
2. **Maturity-score inflation:** several older docs assign very high numerical maturity without corresponding verification artifacts.
3. **"Fully closed" statements:** some prior language marks integration domains fully complete where code still contains framework-first or credential-dependent behavior.

---

## 5) Overall Maturity (Narrative)

- **Strengths:** breadth, modular router design, unified workspace UX direction, rich endpoint agent module set, governance-aware CSPM and enterprise routes.
- **Weaknesses:** uneven implementation depth across advertised domains, documentation drift, and need for stronger contract + regression verification.

**System-wide conclusion:** advanced and highly capable platform, but must keep documentation and maturity framing strictly aligned to concrete implemented code paths.

