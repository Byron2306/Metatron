# Seraph AI Defender - Technical Implementation Roadmap

## Current Code-Logic Snapshot (updated 2026-04-28)

Backend API is FastAPI version `3.0.0` in `backend/server.py`, served on `8001` with health at `/api/health`. The repo has 61 backend router modules plus package init, 32 backend service modules plus package init, 68 JSX frontend pages plus `GraphWorld.tsx`, 68 `<Route` occurrences in `frontend/src/App.js`, unified agent version `2.0.0`, and 63 backend test files. The authenticated frontend hub is `/command`. Root `smoke_test.py` is CAS Shield sidecar code, not a Seraph full-stack health test.


## North-Star Outcome

Deliver a governed adaptive defense fabric whose feature claims are backed by source-derived contracts, deterministic runtime behavior, explicit degraded modes, and security assurance proportional to its breadth.

## Current Baseline

Seraph already has substantial implementation breadth: FastAPI backend, React/Craco frontend, unified agent, MongoDB/Redis data services, compose-managed optional services, email/mobile/MDM/identity/CSPM/deception/governance/AI/world-model/integration paths, 63 backend tests, and dedicated unified-agent regression workflows.

## Workstream A: Contract Integrity

Objective: keep APIs, frontend routes, scripts, and docs synchronized.

Candidate work:

1. Generate a backend route inventory from FastAPI/OpenAPI.
2. Generate a frontend route inventory from `frontend/src/App.js`.
3. Validate frontend API call sites against backend route inventory.
4. Replace stale static counts in docs with generated values or source-derived wording.
5. Track both `/api` and native `/api/v1` route families.

Acceptance signals: docs and validation scripts use `8001` and `/api/health`; `/command` is documented as the main UI hub; route-count changes are visible in CI or release notes.

## Workstream B: Runtime Reliability

Objective: make success and degraded states deterministic.

Candidate work:

1. Standardize dependency health schemas for optional services.
2. Ensure optional ELK/Ollama/WireGuard/security-tool failures do not break core SOC flows.
3. Verify deployment/action success through heartbeat, command result, or external evidence.
4. Add startup checks around dense `backend/server.py` wiring.
5. Clarify required services for each feature family.

Acceptance signals: core stack can be validated with compose status and `/api/health`; optional-service pages report unavailable/degraded states explicitly; response/deployment workflows distinguish queued, running, succeeded, failed, and unavailable states.

## Workstream C: Governance and Security Assurance

Objective: harden autonomous and high-risk action paths.

Candidate work:

1. Expand denial-path tests for auth, policy, token, tool, and governed-dispatch routes.
2. Add replay/TTL/max-use checks where high-risk commands are authorized.
3. Persist and query audit evidence for command decisions and outcomes.
4. Normalize security controls across legacy and secondary app surfaces.
5. Review production CORS, secrets, integration keys, and remote-admin assumptions.

Acceptance signals: high-risk actions have policy reason, principal, trace ID, and outcome evidence; failures are fail-closed or explicitly degraded by feature policy; security regression coverage grows with new route families.

## Workstream D: Production Integration Readiness

Objective: separate framework presence from production-enabled capability.

Candidate work:

1. Document and validate SMTP relay prerequisites for email gateway mode.
2. Document Intune, JAMF, Workspace ONE, and Google Workspace credentials/webhook requirements for MDM.
3. Document cloud credentials and scope requirements for CSPM.
4. Document AI/model-service prerequisites and fallback behavior.
5. Tier integrations by supported, best-effort, and experimental status.

Acceptance signals: feature pages show configuration readiness and last successful sync/test; missing credentials produce actionable errors; release notes distinguish code availability from environment enablement.

## Workstream E: Detection Quality and Operator Experience

Objective: improve trust in detections and operator workflows.

Candidate work:

1. Build repeatable replay scenarios for threat, agent, email, mobile, identity, and cloud signals.
2. Track false positives, suppression decisions, and analyst feedback.
3. Keep workspace tabs focused around current routes rather than legacy page sprawl.
4. Add operator-visible provenance and confidence for AI/Triune outputs.
5. Maintain current setup and validation guidance in the root README.

## Roadmap Guardrails

- Do not claim full production capability for domains that require absent external credentials or host privileges.
- Prefer generated/source-derived documentation for counts and routes.
- Keep compatibility redirects, but document workspace routes as the primary UX.
- Treat root `smoke_test.py` as CAS Shield sidecar code unless it is replaced or renamed.
