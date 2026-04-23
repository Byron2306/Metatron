# Metatron / Seraph Feature Reality Matrix (Code-Backed)

**Last updated:** 2026-04-23  
**Scope:** Current implementation snapshot derived from repository code contracts (not historical release notes or target-state claims).

---

## Legend

- **PASS**: Implemented with active routes/services and normal runtime behavior.
- **PARTIAL**: Implemented but conditional on optional services, credentials, platform specifics, or incomplete hardening/verification depth.
- **LIMITED**: Present as scaffold/compatibility path with constrained operational depth.

---

## 1) Domain Maturity Table

| Domain | Status | Confidence | Primary Evidence |
|---|---|---:|---|
| API Core and Router Fabric | PASS | High | `backend/server.py` |
| Auth, RBAC, Remote Admin Gating | PASS | High | `backend/routers/dependencies.py`, `backend/routers/auth.py` |
| Unified Agent Control Plane | PASS | High | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` |
| Integrations Runtime Orchestration | PASS | High | `backend/routers/integrations.py`, `backend/integrations_manager.py` |
| Governance and Outbound Action Gating | PASS | High | `backend/services/outbound_gate.py`, `backend/services/governed_dispatch.py` |
| Cognition / CCE / Fusion Scoring | PASS | Medium-High | `backend/services/cce_worker.py`, `backend/services/cognition_fabric.py` |
| Threat Correlation and Intel | PASS | Medium-High | `backend/threat_correlation.py`, `backend/threat_intel.py` |
| World Model and Machine Ingest | PASS | High | `backend/routers/world_ingest.py` |
| Email Protection | PASS | Medium-High | `backend/email_protection.py`, `backend/routers/email_protection.py` |
| Email Gateway | PASS | Medium-High | `backend/email_gateway.py`, `backend/routers/email_gateway.py` |
| Mobile Security | PASS | Medium-High | `backend/mobile_security.py`, `backend/routers/mobile_security.py` |
| MDM Connectors | PASS | Medium-High | `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py` |
| CSPM | PASS | High | `backend/routers/cspm.py`, `backend/cspm_engine.py` |
| Kernel / Secure Boot Surfaces | PARTIAL | Medium | `backend/enhanced_kernel_security.py`, `backend/secure_boot_verification.py` |
| Browser Isolation | PARTIAL | Medium | `backend/browser_isolation.py`, `backend/routers/browser_isolation.py` |
| Local AI Augmentation | PARTIAL | Medium | `backend/routers/advanced.py`, `backend/services/cognition_fabric.py` |
| Frontend UX Coverage | PASS | Medium-High | `frontend/src/pages/*`, `frontend/src/lib/api.js` |
| Deployment and Compose Operability | PASS | Medium-High | `docker-compose.yml`, `docker-compose.prod.yml`, `nginx/conf.d/default.conf` |

---

## 2) Contract-Level Reality by Domain

### 2.1 API Core and Security

| Capability | Status | Notes |
|---|---|---|
| `/api`-prefixed router composition | PASS | Main backend mounts broad router set under `/api`; some routers include their own `/api/v1` prefixes. |
| Production internal token requirement | PASS | `INTEGRATION_API_KEY` is required in production startup path. |
| Strict CORS behavior | PASS | Wildcard CORS is blocked in production/strict mode. |
| JWT hardening semantics | PASS | Weak/missing JWT secret fails in strict/production mode. |
| Remote admin access gate | PASS | Non-local requests are constrained by admin role/email rules when enabled. |

### 2.2 Unified Agent and Command Plane

| Capability | Status | Notes |
|---|---|---|
| Agent registration / heartbeat | PASS | `/api/unified/agents/register`, `/api/unified/agents/{id}/heartbeat`. |
| Command polling / result reporting | PASS | `/api/unified/agents/{id}/commands`, `/command-result`. |
| Agent-side monitor breadth | PASS | Monolithic `UnifiedAgent` includes broad monitor set including email/mobile tracks. |
| Local execution governance hooks | PASS | Endpoint command execution paths integrate gating/broker logic. |
| Trusted-network auth fallback | PARTIAL | Optional and security-sensitive (`UNIFIED_AGENT_ALLOW_TRUSTED_NETWORK_AUTH`). |

### 2.3 Integrations and Runtime Tools

| Capability | Status | Notes |
|---|---|---|
| Server-side runtime execution | PASS | `run_runtime_tool(... runtime_target="server")` supported for allowlisted tools. |
| Unified-agent runtime queueing | PASS | `runtime_target` can queue agent runtime commands through governance dispatch. |
| Tool allowlist enforcement | PASS | Backed by `SUPPORTED_RUNTIME_TOOLS` and agent-side allowlist checks. |
| Machine-token access for jobs/ingest | PASS | Integrations router supports machine-token auth flow. |

### 2.4 Cognition and Correlation

| Capability | Status | Notes |
|---|---|---|
| CCE session analysis worker | PASS | Worker groups CLI commands, scores machine likelihood, stores summaries. |
| Cognitive pressure fusion score | PASS | Fusion logic combines AATL, CCE, ML, and AI uncertainty signals. |
| Threat intel/correlation pipeline | PASS | Correlation engine remains distinct from cognition fusion path. |
| Autonomy tier recommendation | PASS | Tier recommendation derived from fused score thresholds. |

### 2.5 Email / Mobile / MDM

| Capability | Status | Notes |
|---|---|---|
| Email protection pipeline | PASS | SPF/DKIM/DMARC + phishing/attachment/impersonation logic present. |
| Email gateway quarantine/list/policy APIs | PASS | Stats, process, quarantine ops, block/allow list, policies are exposed. |
| Mobile security workflows | PASS | Device registration, threat checks, compliance and policy paths present. |
| MDM connector lifecycle | PASS | Add/remove/connect/disconnect/sync/device actions implemented. |
| Production external integration readiness | PARTIAL | Requires real SMTP/MDM credentials and external platform connectivity. |

### 2.6 Deployment Reality

| Capability | Status | Notes |
|---|---|---|
| Core Compose stack | PASS | Mongo, Redis, backend, frontend are first-class services. |
| Optional profiles (security/sandbox/bootstrap) | PASS | Trivy/Falco/Suricata/Zeek/Volatility and Cuckoo are profile-structured. |
| Production override discipline | PASS | Prod override hides direct backend/frontend ports and enables strict env. |
| Nginx ingress | PARTIAL | Requires SSL artifacts/config; local HTTP-only assumptions can drift. |

---

## 3) Confirmed Constraints and Gaps

1. **Multiple agent surfaces exist**  
   The monolithic unified-agent API contract differs from desktop/web auxiliary agent surfaces and must be documented distinctly.

2. **Credential-bound integrations remain conditional**  
   Email gateway and MDM connectors are materially implemented but full enterprise behavior depends on external credentials and reachable providers.

3. **Browser isolation depth is partial**  
   URL filtering/sanitization exists, but full remote browser isolation architecture is not fully represented.

4. **Auxiliary docs/scripts can drift from active contracts**  
   Example patterns include legacy ports, stale health paths, or cloud-default script URLs.

---

## 4) Operational Reality Statement

Current code supports a broad, functioning security platform with:

- Production-aware API security controls,
- Unified-agent registration/heartbeat/command lifecycle,
- Governed high-impact action queueing,
- Multi-domain features (email, mobile, MDM, CSPM, SOAR, correlation),
- Compose-based deployment with clear optional service profiles.

Remaining work is concentrated in hardening consistency, integration credentialing, and deeper assurance/testing depth, not missing foundational feature surfaces.
