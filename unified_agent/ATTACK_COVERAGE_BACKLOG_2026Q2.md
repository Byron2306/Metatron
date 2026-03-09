# ATT&CK Coverage Backlog (System-Wide)

## Scope and Baseline

This backlog covers the full platform, not just endpoint code:
- Unified agent endpoint runtime and local UI (port 5000)
- Remote backend APIs, analytics, ingestion, and SOAR
- Fleet-level telemetry and cross-domain correlation

Current baseline (measured in code-referenced ATT&CK IDs):
- Covered techniques/sub-techniques in code: 134
- Active MITRE Enterprise techniques/sub-techniques not covered: 563
- Top-level techniques covered: 60/216

Important: ATT&CK "coverage" here means detection-ready implementation (telemetry + logic + validation), not just ID references.

## Coverage Quality Model (Required for all stories)

Every technique must be scored before it is counted as covered:
- 0: No telemetry source
- 1: Telemetry ingested only
- 2: Rule/logic exists
- 3: High-fidelity detection in production
- 4: Validated with adversary emulation
- 5: Automated response linked in SOAR

Backlog success KPI:
- Raise as many techniques as possible to score >= 3
- Target score >= 4 for critical techniques in credential access, lateral movement, exfiltration, and impact

## Prioritized Epic Backlog

## Epic 1 (P0): Identity and Token Abuse Detection

Owner split:
- Backend: identity ingestion, correlation, response automation
- Unified agent: local credential-access and token artifact signals

Stories:
1. Integrate Entra ID/Azure AD sign-in and audit logs into backend ingestion.
2. Integrate Okta system logs and session events.
3. Add M365 OAuth consent/app grant telemetry ingestion.
4. Implement token abuse analytics (suspicious token reuse, impossible travel with token continuity).
5. Add endpoint-side detection for metadata token harvest commands and cloud credential scraping artifacts.
6. Add SOAR playbooks: revoke sessions, disable account, rotate secrets.

Primary ATT&CK families improved:
- T1078, T1078.004, T1528, T1550.*, T1552.*

Estimated net newly covered techniques:
- +35 to +55

Acceptance criteria:
- Mapped detections for at least 20 identity techniques with score >= 3
- 8 high-risk identity techniques validated with emulation (score >= 4)

## Epic 2 (P0): Cloud Control Plane + Data Exfil Visibility

Owner split:
- Backend: AWS/Azure/GCP connectors, normalization, detection, risk scoring
- Unified agent: cloud CLI behavior enrichment (aws/az/gsutil/rclone)

Stories:
1. Add AWS CloudTrail + Config + GuardDuty event pipeline.
2. Add Azure Activity + Defender + Storage audit pipeline.
3. Add GCP Audit Logs + SCC ingestion.
4. Implement cloud storage exfil detection (bulk object access, unusual destination, staged transfer).
5. Implement cross-account role abuse and API key misuse detections.
6. Correlate endpoint cloud CLI behavior with cloud API activity.

Primary ATT&CK families improved:
- T1530, T1567.002, T1078.004, T1528, T1552.005, T1578.*, T1580

Estimated net newly covered techniques:
- +45 to +70

Acceptance criteria:
- 3 cloud providers integrated with normalized event schema
- 15 cloud techniques at score >= 3
- 6 cloud exfil techniques at score >= 4

## Epic 3 (P0): Network Detection Depth (NDR)

Owner split:
- Backend: network telemetry ingestion, analytics, correlation
- Unified agent: local DNS and process-to-connection enrichment

Stories:
1. Add Zeek logs ingestion and parser.
2. Expand Suricata EVE parser beyond alert-only to flow/http/dns/tls records.
3. Add DNS anomaly and tunneling detector with baselines.
4. Add beaconing detector (interval regularity + low-volume persistence).
5. Link endpoint process lineage to network sessions in threat timeline.

Primary ATT&CK families improved:
- T1071.*, T1095, T1041, T1048.*, T1571, T1568.*

Estimated net newly covered techniques:
- +30 to +50

Acceptance criteria:
- 10 C2/exfil techniques at score >= 3
- 4 C2 techniques validated with replay/emulation at score >= 4

## Epic 4 (P1): Endpoint Deep Telemetry and EDR Logic Expansion

Owner split:
- Backend: centralized detection management and tuning
- Unified agent: event collection and on-host detectors

Stories:
1. Add Sysmon-to-backend normalization (Windows).
2. Add Linux auditd/journald normalization and process ancestry fidelity.
3. Add osquery pack integration for scheduled sweeps.
4. Implement richer injection and credential-access variant detections.
5. Add persistence and defense-evasion detectors beyond registry/process heuristics.
6. Add local confidence scoring and suppression framework.

Primary ATT&CK families improved:
- T1003.*, T1055.*, T1547.*, T1562.*, T1027, T1036

Estimated net newly covered techniques:
- +40 to +65

Acceptance criteria:
- 25 endpoint techniques at score >= 3
- False positive rate trend dashboard in backend

## Epic 5 (P1): Container and Kubernetes Runtime Coverage

Owner split:
- Backend: K8s audit ingestion, container analytics, policy engine
- Unified agent: local runtime tool orchestration and signal forwarding

Stories:
1. Ingest Kubernetes audit logs and map ATT&CK for containers.
2. Add container runtime event normalization (Falco + native runtime events).
3. Add admission-control and image policy telemetry.
4. Add SBOM/signature trust checks and drift detection.
5. Expand command functions to include structured container findings payloads.

Primary ATT&CK families improved:
- T1610, T1611, T1525, T1552.* (container secrets), T1609, T1613

Estimated net newly covered techniques:
- +20 to +35

Acceptance criteria:
- 10 container techniques at score >= 3
- Runtime exploit simulation test pack integrated in CI

## Epic 6 (P1): Email/Collaboration/SaaS Attack Surface

Owner split:
- Backend: SaaS ingestion and cross-domain correlation
- Unified agent: endpoint follow-on execution and payload chain linkage

Stories:
1. Add M365 and Google Workspace audit event pipelines.
2. Add Teams/Slack app install and token grant monitoring.
3. Correlate phishing-to-process execution chain.
4. Add suspicious OAuth app and mailbox rule abuse detections.

Primary ATT&CK families improved:
- T1566.*, T1114.*, T1098.*, T1078.*, T1204.*

Estimated net newly covered techniques:
- +20 to +35

Acceptance criteria:
- 12 SaaS/email techniques at score >= 3
- 5 high-risk techniques validated at score >= 4

## Epic 7 (P2): CI/CD and Software Supply Chain

Owner split:
- Backend: SCM and pipeline telemetry ingestion
- Unified agent: runner endpoint hardening telemetry

Stories:
1. Integrate GitHub/GitLab audit logs and Actions/runner events.
2. Add artifact registry and signing/attestation verification telemetry.
3. Add pipeline secret exposure and anomalous workflow execution detection.
4. Add SOAR playbooks for token revoke, runner isolate, artifact quarantine.

Primary ATT&CK families improved:
- T1195.*, T1552.*, T1550.*, T1608.*, T1587

Estimated net newly covered techniques:
- +15 to +30

Acceptance criteria:
- 8 supply-chain techniques at score >= 3
- End-to-end incident drill executed and documented

## Epic 8 (P2): Validation, Test Harness, and ATT&CK Governance

Owner split:
- Backend: coverage service + dashboard + policy gates
- Unified agent: controlled simulation hooks and local validation harness

Stories:
1. Build ATT&CK coverage service with per-technique quality score.
2. Add weekly emulation jobs (Atomic Red Team/Caldera scenarios).
3. Add CI gate: no new ATT&CK-mapped detector can merge without test evidence.
4. Add backlog auto-generation from uncovered and shallow techniques.

Primary ATT&CK families improved:
- All tactics through improved validation depth

Estimated net newly covered techniques:
- +0 to +10 direct, but large quality increase across existing coverage

Acceptance criteria:
- ATT&CK dashboard live in backend
- 30 critical techniques at score >= 4 by end of phase

## Unified Agent UI and Command Backlog (Tooling Monitors)

These are specifically for Trivy/Falco/Suricata/Volatility and align with recent command work.

Stories:
1. Add monitor cards and API routes (done baseline): trivy/falco/suricata/volatility status.
2. Add command execution widgets per tool (run status/scan from local UI).
3. Add result history pane (last 20 runs) and state transitions.
4. Add normalized finding schema to display vulnerabilities/runtime alerts consistently.
5. Add backend correlation link-outs from local tool findings.

Acceptance criteria:
- Operator can trigger and inspect tool runs from local UI without CLI.
- Results are persisted and visible in backend timeline/correlation.

## 30/60/90 Delivery Plan

Day 0-30 (must ship):
1. Epic 1 identity ingestion foundation + token abuse baseline detections.
2. Epic 2 cloud ingestion for at least AWS + one additional provider.
3. Epic 3 Suricata EVE + DNS baseline detector.
4. Tooling monitor cards fully interactive (run + status + result panel).

Expected gain by day 30:
- +60 to +90 techniques newly covered
- 20+ critical techniques raised to score >= 3

Day 31-60:
1. Epic 4 endpoint deep telemetry rollout (Sysmon + auditd pipeline).
2. Epic 5 container/k8s analytics baseline.
3. Epic 6 email/collab ingestion and phishing-chain correlation.

Expected gain by day 60:
- cumulative +120 to +185 newly covered
- 35+ critical techniques at score >= 3

Day 61-90:
1. Epic 7 CI/CD supply-chain telemetry and detections.
2. Epic 8 ATT&CK governance dashboard + emulation gate.
3. Quality uplift sprint to move shallow techniques to medium/strong.

Expected gain by day 90:
- cumulative +155 to +245 newly covered
- 30 critical techniques at score >= 4

## Execution Notes

1. Track all stories with ATT&CK IDs in acceptance criteria.
2. Do not count a technique as covered unless score >= 3.
3. Keep a separate quality burndown for shallow techniques.
4. Prioritize detection quality over raw count inflation.

## Immediate Next 10 Tickets (Ready to Start)

1. Backend: Entra ID sign-in and audit log connector.
2. Backend: AWS CloudTrail ingest + parser + ATT&CK mapper.
3. Backend: Suricata EVE flow/http/dns/tls parser expansion.
4. Backend: ATT&CK coverage score API endpoint.
5. Backend: SOAR playbook - revoke token + disable account.
6. Agent: cloud CLI enrichment for aws/az/gsutil/rclone commands.
7. Agent: process-to-network session correlation payload.
8. UI(5000): tooling monitor action buttons + command invocation panel.
9. UI(5000): tooling run result timeline panel.
10. Tests: ATT&CK quality regression suite for top 20 critical techniques.
