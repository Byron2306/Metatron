# Metatron / Seraph Architecture Map

Updated: 2026-04-26

## 1. Runtime topology

The active platform is a full-stack security control plane:

- `frontend/`: React 19 + React Router + CRACO dashboard.
- `backend/`: FastAPI API, WebSockets, MongoDB access, domain routers, and service orchestration.
- `unified_agent/`: endpoint agent, desktop UI, local web UI, standalone agent API, and tool-integration parsers.
- `docker-compose.yml`: local/container stack with MongoDB, Redis, backend, frontend, Celery worker/beat, Elasticsearch/Kibana, WireGuard, Ollama, and profile-gated security/sandbox services.
- `memory/`, `docs/`, `test_reports/`: review documents, architecture collateral, and validation reports.

## 2. Backend composition

`backend/server.py` is the central app entrypoint. It:

1. Creates the FastAPI application.
2. Connects MongoDB and injects the database into dependency helpers.
3. Initializes world-model and triune service instances.
4. Registers the large router mesh under `/api` plus selected native `/api/v1` routers.
5. Exposes health and WebSocket channels.

Major router families:

- Core platform: auth, dashboard, settings, reports, audit, websocket.
- Security analytics: threats, alerts, threat intel, hunting, correlation, timeline, MITRE, Sigma, Zeek, osquery.
- Response plane: response, quarantine, SOAR, ransomware, honeypots, honey tokens, deception.
- Endpoint plane: agents, agent commands, swarm, unified agent, CLI events.
- Enterprise and identity plane: enterprise, multi-tenant, zero trust, CSPM, identity, governance.
- Advanced plane: advanced services, AI analysis, AI threats, ML prediction, sandbox, browser isolation, VNS, MCP, vector memory, quantum.
- Domain expansion: email protection, email gateway, mobile security, MDM connectors, kernel sensors, secure boot, attack paths.

## 3. Frontend composition

`frontend/src/App.js` defines protected dashboard routing. Current navigation favors consolidated workspaces:

- `/command`
- `/ai-activity`
- `/response-operations`
- `/investigation`
- `/detection-engineering`
- `/email-security`
- `/endpoint-mobility`
- `/unified-agent`
- `/world`

Older specific routes remain as redirects where possible, for example alerts/threats route into `/command`, email gateway/protection route into `/email-security`, and mobile/MDM route into `/endpoint-mobility`.

## 4. World model and triune cognition flow

The implemented strategic loop is:

1. Routers/services call `emit_world_event` in `backend/services/world_events.py`.
2. The emitter classifies the event as passive, local reflex, strategic recompute, or action-critical recompute.
3. Strategic and action-critical events invoke `TriuneOrchestrator.handle_world_change`.
4. The orchestrator builds a world snapshot from entities, edges, campaigns, hotspots, active responses, trust state, and attack-path metrics.
5. `CognitionFabricService` enriches the snapshot with CCE/AATL/AATR/AI reasoning signals when available.
6. `MetatronService` assesses strategic pressure, cognitive pressure, autonomy confidence, recommended posture, and policy tier.
7. `MichaelService` ranks candidate actions using explainable keyword, risk, recency, degree, and optional AI explanations.
8. `LokiService` challenges the plan with alternative hypotheses, hunt suggestions, deception options, uncertainty markers, and action dissent.

## 5. Governance and high-impact action gating

High-impact outbound actions are governed by `OutboundGateService` and `GovernedDispatchService`:

- Mandatory gated action types include agent commands, swarm commands, response block/unblock, quarantine restore/delete, tool execution, MCP tool execution, and cross-sector hardening.
- Gated actions are persisted to `triune_outbound_queue` and `triune_decisions`.
- Governed agent commands are stored with `gated_pending_approval`, `queue_id`, `decision_id`, and authority/decision metadata.
- `backend/routers/governance.py` exposes pending decision listing, approval, denial, and executor run-once endpoints.
- `GovernanceExecutorService` translates approved decisions into executable domain actions.

## 6. Unified agent architecture

`unified_agent/core/agent.py` is the main endpoint agent module. It contains monitor classes for process, network, registry, process tree, LOLBins, code signing, DNS, memory, application control, DLP, vulnerability, AMSI, ransomware, rootkit, kernel security, self-protection, identity, auto-throttle, firewall, WebView2, CLI telemetry, hidden files, alias/rename, privilege escalation, email protection, mobile security, and YARA.

Supporting surfaces:

- `backend/routers/unified_agent.py`: central backend control-plane API.
- `unified_agent/server_api.py`: standalone FastAPI service with in-memory agent state and backend proxying.
- `unified_agent/ui/desktop/main.py`: Tk desktop UI.
- `unified_agent/ui/web/app.py`: Flask local web UI that reuses desktop logic.
- `unified_agent/integrations/*`: parsers/adapters for tools such as Amass, Arkime, BloodHound, PurpleSharp, and SpiderFoot.

## 7. Memory and evidence systems

Do not confuse the `memory/` directory with runtime vector memory:

- `memory/` is documentation and review collateral.
- Runtime semantic memory is `backend/services/vector_memory.py`.
- API endpoints live in `backend/routers/advanced.py` under `/api/advanced/memory/*`.
- Memory entries include namespace, trust level, provenance, evidence references, related entries, case linkage, embeddings, and lifecycle metadata.

## 8. Optional services and degraded mode

MongoDB, backend, and frontend are required for core health. Redis is part of the current compose runtime for Celery. Elasticsearch/Kibana, WireGuard, Ollama, Trivy, Falco, Suricata, Cuckoo, external SMTP, MDM platforms, and notification providers are optional or profile/integration dependent.

Correct behavior for optional services is explicit degraded status, not core dashboard failure.

## 9. Main architectural risks

- `backend/server.py` is still a dense central wiring point.
- The API surface is broad enough that contract drift remains a real risk.
- Some domain services are in-memory or framework-first unless external credentials/providers are configured.
- Governance is now materially persisted for high-impact decisions, but scale/restart semantics should keep receiving test coverage.
- Documentation and scripts may lag current route consolidation and runtime behavior.
