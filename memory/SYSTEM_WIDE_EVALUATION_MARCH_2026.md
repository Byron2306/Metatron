# Metatron/Seraph - System-Wide Evaluation (Rebaseline)

**Date:** 2026-04-18  
**Scope:** Repository-wide code-evidence refresh of prior March system-wide assessments

---

## Executive Summary

The platform is still high-capability and feature-dense, with major strengths in:

- unified endpoint/agent control surfaces,
- governance-aware enterprise control plane components,
- broad SOC + response + advanced analytics integration.

Compared to earlier snapshots, the key correction is **precision in maturity claims**: several domains previously labeled as fully complete are better classified as **implemented with conditional depth** (for example MDM breadth and some external-integration dependent surfaces).

---

## Current Architecture Reality

### Backend/API
- `backend/server.py` registers a wide router surface with mixed prefixes:
  - `/api/*` routers for most domains
  - `/api/v1/*` on selected routers (e.g., CSPM, identity, attack-path/secure-boot/kernel sensor routers)
- Router inventory:
  - 62 router files in `backend/routers`
  - ~694 route decorators (GET/POST/PUT/DELETE/PATCH)
  - 65 `include_router(...)` registrations in server wiring

### Agent Plane
- Unified agent core in `unified_agent/core/agent.py`
- 27 instantiated monitor modules (including email and mobile monitors) feeding telemetry/heartbeat pathways.

### Runtime Stack
- `docker-compose.yml` includes a broad default stack:
  - mongodb, redis, backend, frontend
  - celery worker/beat
  - elasticsearch, kibana, ollama
  - wireguard, nginx
  - optional profile-gated security/sandbox services (trivy, falco, suricata, zeek, cuckoo, volatility tooling).

---

## Domain-by-Domain Reassessment

| Domain | Updated Status | Code-Evidence Summary |
|---|---|---|
| Unified Agent + Fleet APIs | PASS | Registration, heartbeat, commands, deployments, monitor status and installer endpoints under `/api/unified/*`. |
| EDM governance | PASS | Dataset versioning, publish gates, staged rollouts, readiness checks, rollback and telemetry are implemented in unified router. |
| Email Protection | PASS | DNS auth checks, URL/attachment analysis, impersonation and DLP logic are implemented and exposed by API. |
| Email Gateway | PASS | Inline decision engine, policy thresholds, quarantine, allow/block lists, and processing endpoint are real. |
| Mobile Security | PASS | Device registration/status, app analysis, threat lifecycle, compliance and dashboard APIs are implemented. |
| MDM Connectors | PARTIAL PASS | Router and platform metadata include Intune/JAMF/Workspace ONE/Google Workspace, but service-level concrete connectors currently exist for Intune + JAMF. |
| Identity Protection | PASS/PARTIAL | Durable incident state transitions and provider event ingestion are present; quality depends on upstream identity telemetry and operational policy tuning. |
| CSPM | PASS/PARTIAL | Auth-required scan, durable scans/findings, transition controls and provider persistence are implemented; writes are triune-gated and operational depth depends on configured credentials/providers. |
| Enterprise governance plane | PASS | Policy/token/tool/telemetry endpoints with outbound-gated high-impact operations and governance decision workflows are implemented. |
| Browser Isolation | PARTIAL | Session/url-analysis/sanitize/blocklist are implemented; full enterprise-grade remote isolation depth remains limited. |
| Deployment Realism | PASS/PARTIAL | Real SSH/WinRM deployment exists; simulation is guarded behind env flag and should be treated as controlled demo mode only. |

---

## Key Corrections from Older March Documents

1. **MDM breadth correction**
   - Prior docs stated all 4 connector implementations as fully mature.
   - Current service implementation provides concrete connector classes for Intune and JAMF, with broader platform identifiers exposed at API/platform metadata level.

2. **CSPM hardening correction**
   - `POST /api/v1/cspm/scan` now requires authenticated user dependency.
   - Additional durability/state-transition controls exist for scans/findings and provider operations are outbound-gated.

3. **Deployment truth correction**
   - Deployment logic is not purely simulated; real deployment methods are implemented.
   - Simulation only occurs when explicitly enabled (`ALLOW_SIMULATED_DEPLOYMENTS=true`) and credentials are absent.

4. **Maturity framing correction**
   - The platform is strong and usable, but some old documents overstated blanket enterprise parity across all integration depths.

---

## Risk and Technical Debt (Current)

### High-value risks
1. Contract drift risk across large API footprint and mixed route versioning.
2. Provider-depth mismatch risk when API advertises broader capability than current concrete connector implementation.
3. Assurance debt risk on denial-path and resilience test coverage for fast-moving domains.

### Medium-value risks
1. Optional integration behavior still requires strict operator run-mode discipline.
2. Legacy compatibility paths can increase operational ambiguity without clear deprecation sequencing.

---

## Updated Strategic Recommendations

### Immediate
1. Keep memory/docs aligned with concrete implementation depth (especially MDM and integration-dependent features).
2. Extend contract tests around high-change endpoints (unified, enterprise, CSPM, identity).
3. Add explicit docs badges for "implemented API surface" vs "full provider depth".

### Near-term
1. Complete additional MDM connector classes or clearly mark platform support tiers.
2. Expand hardening/denial-path tests in governance and deployment pathways.
3. Normalize endpoint versioning patterns where practical (`/api` vs `/api/v1` consistency strategy).

---

## Final Assessment

The platform is a strong, advanced multi-domain security system with substantial real implementation. The most important improvement now is **precision and governance of maturity claims**: keep documentation, product assertions, and code-evidence in strict alignment so operational teams and stakeholders have a reliable source of truth.

