# Seraph Observation Core & Suricata Promotion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Build the first production-grade evidence-fabric vertical slice: source-native Suricata alert evidence becomes a restart-safe canonical observation, is promoted only on material change, and projects exactly once into canonical world events/entities without triggering Triune.

**Architecture:** Add one focused observation_fabric service between source-native evidence and the existing world-state seams. Keep services.vns responsible for sensor-native truth, reuse WorldModelService and emit_world_event, and make durability/index guarantees source-controlled at backend startup. Do not modify Harmonic, Chorus, Token Broker, MCP, Tool Gateway, Zeek semantics, or governance world-state hashes in this plan.

**Tech Stack:** Python 3, FastAPI, Motor/PyMongo, Pydantic-compatible models, pytest + pytest-asyncio, existing Seraph services.

**Spec:** docs/superpowers/specs/2026-10-08-seraph-symphonic-evidence-fabric-design.md

## Global Constraints

- Proven code is read-only by default. No unrelated refactors.
- Preserve canonical MCP, Token Broker, Tool Gateway PEP, Chorus truth, and existing Harmonic framework.
- Preserve the Unified Agent 29-surface census and no-Docker-socket boundary.
- Preserve Zeek VNS behavior.
- Preserve Suricata flow/DNS/alert semantic separation and restart-safe source identity.
- Historical Suricata evidence without world_fanout_status=pending must not be retroactively promoted.
- Sensor observation, analytic interpretation, governance decision, and execution authority remain distinct.
- Retained observations do not trigger Triune; materially promoted observations use the world-event classification policy and trigger recomputation.
- Do not modify WorldModelService.current_world_state_hash or WorldManifoldService hashing in this plan. Their authority semantics require a separate audit.
- No production-code change without a failing test observed first.
- No PASS claim without fresh runtime evidence.
- Before execution, inspect the local working tree. Local Phase 4 changes are authoritative over remote copies for modified files. Never reset, overwrite, or discard them.
- Before creating an isolated worktree, preserve the local Phase 4 working tree in a commit or other user-approved recoverable form.

## Scope Boundary

This plan implements only:

~~~text
Suricata durable alert evidence
→ canonical observation
→ material-change promotion
→ canonical world_event
+ canonical alert entity
~~~

It deliberately does not implement cross-witness reconciliation, Arkime, Hunting local/remote adaptation, Harmonic input, Chorus evidence participation, continuous ingestion, WireGuard, or governance/manifold hash mutation.

## Review Focus

1. Concurrent duplicate claims: two requests race on one Suricata event. One observation and one world event survive.
2. Crash between projection steps: entity upsert succeeds but source status does not. Replay converges without a second world event.
3. Historical evidence: old unmarked Suricata alert documents never flood the new rail.
4. Persistence failure: failed world-event persistence leaves evidence retryable and cannot be reported as emitted.
5. Non-JSON-safe payload: hashing fails closed instead of using default=str.

---

### Task 1: Canonical Observation Contract

**Files**
- Create: backend/services/observation_fabric.py
- Create: backend/tests/test_observation_fabric.py

**Interfaces**
- CanonicalObservation
- canonical_json(value: Any) -> str
- evidence_digest(payload: Dict[str, Any]) -> str
- build_observation(...source-native fields...) -> CanonicalObservation

Required fields:
schema, observation_id, witness, source_kind, source_event_type, source_event_id, observed_at, ingested_at, entity_refs, reconciliation_scope, native_severity, native_confidence, provenance, evidence_digest, payload, promotion_state.

- [ ] Step 1: Write failing tests:
  - test_build_observation_preserves_source_identity_and_witness
  - test_observation_id_is_deterministic_for_same_source_identity
  - test_evidence_digest_is_order_independent_for_json_objects
  - test_canonical_json_rejects_non_json_safe_values

- [ ] Step 2: Verify RED.

Run:

~~~bash
PYTHONPATH=. python -m pytest -q backend/tests/test_observation_fabric.py
~~~

Expected: import/feature failure because observation_fabric does not yet exist.

- [ ] Step 3: Implement minimal model and hashing.

Pinned values:
- schema = seraph.observation.v1
- observation_id = obs- plus first 24 hex chars of SHA-256 over witness|source_event_type|source_event_id
- UTC ISO-8601 ingested_at
- strict canonical JSON with sorted keys and compact separators
- no default=str
- initial promotion_state = pending

- [ ] Step 4: Verify GREEN with the same command.
- [ ] Step 5: Commit with message: feat: add canonical observation contract

---

### Task 2: Durable Observation Store and Source-Controlled Indexes

**Files**
- Modify: backend/services/observation_fabric.py
- Modify: backend/server.py in the existing startup/index path
- Modify: backend/tests/test_observation_fabric.py

**Interfaces**
- ObservationStore(db)
- await ObservationStore.ensure_indexes() -> None
- await ObservationStore.claim(observation) -> bool
- await ObservationStore.get(observation_id) -> Optional[dict]

Collections:
- canonical_observations
- observation_material_state

Required indexes:
- unique canonical_observations.observation_id
- unique compound canonical_observations(witness, source_event_type, source_event_id)
- unique observation_material_state.material_key
- partial unique world_events.payload.observation_id for type=observation_promoted
- partial unique vns_flows.source_event_id for witness=suricata
- partial unique vns_dns_queries.source_event_id for witness=suricata
- partial unique suricata_alert_evidence.source_event_id for witness=suricata

Use the existing Phase 4 index names where already established:
- uniq_suricata_flow_source_event_id
- uniq_suricata_dns_source_event_id
- uniq_suricata_alert_source_event_id

This makes the manually proven Phase 4 durability guarantees reproducible on a fresh deployment.

- [ ] Step 1: Write failing tests:
  - test_observation_store_claims_source_identity_once
  - test_observation_store_duplicate_claim_returns_false
  - test_ensure_indexes_declares_required_unique_indexes
  - test_concurrent_duplicate_claim_converges_to_one_observation

- [ ] Step 2: Verify RED.
- [ ] Step 3: Implement atomic Mongo setOnInsert claims. Mongo is authority, not RAM. Duplicate-key races are existing evidence, not record errors. Do not alter Zeek collections.
- [ ] Step 4: Verify GREEN.
- [ ] Step 5: Commit: feat: persist canonical observation identity

---

### Task 3: Suricata Alert → Canonical Observation Adapter

**Files**
- Modify: backend/services/observation_fabric.py
- Create: backend/tests/test_suricata_observation_bridge.py
- Read-only verification before edits: current local backend/services/vns.py

**Interfaces**
- suricata_alert_to_observation(evidence) -> CanonicalObservation
- SuricataObservationBridge(db)
- await SuricataObservationBridge.claim_pending(limit: int = 250) -> dict

Consumes only durable suricata_alert_evidence where witness=suricata and world_fanout_status=pending.

Mapping:
- source_kind = network_ids
- source_event_type = alert
- preserve source_event_id
- reconciliation_scope = network_alert
- typed entity refs such as ip:172.28.0.4
- preserve native severity, signature_id, signature, category, action, tuple, metadata, interface, and direction
- never invent ATT&CK IDs
- never convert alert to VNS flow

Source evidence transitions:
pending → observed for a new canonical claim
pending → reconciled when observation already exists
Both store observation_id.

- [ ] Step 1: Write failing tests:
  - test_suricata_alert_maps_without_flattening_native_classification
  - test_suricata_adapter_does_not_promote_historical_unmarked_alerts
  - test_suricata_bridge_claims_only_pending_evidence
  - test_suricata_bridge_reconciles_existing_observation_after_restart
  - test_suricata_adapter_rejects_missing_source_event_id_without_marking_emitted

- [ ] Step 2: Verify RED.

~~~bash
PYTHONPATH=. python -m pytest -q backend/tests/test_suricata_observation_bridge.py
~~~

- [ ] Step 3: Implement downstream adapter. Do not edit proven Suricata flow/DNS/alert parsing or source claims in services/vns.py unless a failing test proves the downstream design impossible.
- [ ] Step 4: Verify GREEN.
- [ ] Step 5: Commit: feat: normalize Suricata alerts into observations

---

### Task 4: Material-Change Promotion Policy

**Files**
- Modify: backend/services/observation_fabric.py
- Modify: backend/tests/test_observation_fabric.py

**Interfaces**
- PromotionDecision
- SuricataAlertPromotionPolicy.material_key(observation) -> str
- SuricataAlertPromotionPolicy.material_digest(observation) -> str
- await PromotionService(db).evaluate(observation) -> PromotionDecision

Suricata material_key is direction-aware using Suricata's own to_server/to_client semantics. This is service/initiator normalization, not Hunting local/remote inference.

For direction=to_server:

~~~text
network_alert
| signature_id
| initiator_ip=src_ip
| service_ip=dst_ip
| service_port=dst_port
| protocol
~~~

For direction=to_client, reverse the endpoint roles. If direction is absent/unknown, use a deterministic neutral endpoint ordering and omit an inferred service port rather than inventing roles.

material_digest includes action, category, severity, signature text, relevant native metadata, and stable service context. It excludes volatile timestamp, source-event identity, and the initiator's ephemeral port.

Decision kinds:
- novel_material_observation → promote
- material_change → promote
- repeat_without_material_change → retain_without_promotion

Cross-witness corroboration/contradiction is deferred to the reconciliation plan.

- [ ] Step 1: Write failing tests:
  - test_first_material_alert_promotes
  - test_same_material_alert_with_new_source_event_is_retained_without_promotion
  - test_severity_change_promotes
  - test_category_change_promotes
  - test_concurrent_same_material_state_promotes_once

- [ ] Step 2: Verify RED.
- [ ] Step 3: Implement atomic material-state compare/update in Mongo. No RAM last-seen map.
- [ ] Step 4: Verify GREEN.
- [ ] Step 5: Commit: feat: gate observation promotion on material change

---

### Task 5: Exact-Once Canonical World Projection

**Files**
- Modify: backend/services/world_events.py
- Modify: backend/services/observation_fabric.py
- Modify: backend/tests/test_observation_fabric.py

**Interfaces**
- Add backward-compatible strict_persistence: bool = False to emit_world_event(...)
- WorldObservationProjector(db)
- await WorldObservationProjector.project(observation, decision) -> dict

Projection:
- deterministic WorldEntity of type alert from promotion material key
- preserve observation_id, witness, source classification, evidence_digest, observed time
- do not synthesize strategic risk
- emit type=observation_promoted
- payload schema=seraph.observation.world.v1
- payload includes observation_id, witness, promotion reason, evidence_digest, material_key
- promoted observations trigger Triune; retained observations do not
- source=observation_fabric
- do not change current_world_state_hash
- do not rebuild WorldManifoldService

- [ ] Step 1: Write failing tests:
  - test_promoted_observation_creates_alert_entity_and_world_event
  - test_retained_observation_creates_no_world_event
  - test_projection_replay_keeps_one_world_event
  - test_crash_after_entity_upsert_reconciles_to_one_world_event
  - test_world_event_persistence_failure_does_not_report_emitted
  - test_projection_never_triggers_triune
  - test_emit_world_event_strict_persistence_raises_on_insert_failure

- [ ] Step 2: Verify RED.
- [ ] Step 3: Add strict persistence as an optional behavior. Existing callers keep best-effort default behavior.
- [ ] Step 4: Implement projector using existing WorldModelService.upsert_entity() and emit_world_event().
- [ ] Step 5: Verify GREEN.
- [ ] Step 6: Run authority regression:

~~~bash
PYTHONPATH=. python -m pytest -q authority_tests/test_seraph_authority_chain.py --confcutdir=authority_tests
~~~

- [ ] Step 7: Commit: feat: project promoted observations into world state

---

### Task 6: Wire Existing Suricata Ingest Route and Prove Runtime Durability

**Files**
- Modify: backend/routers/advanced.py only at existing POST /vns/suricata/ingest
- Modify: backend/tests/test_suricata_observation_bridge.py

**Produces**
An additive observation_fabric response object with:
claimed, reconciled, promoted, retained_without_promotion, projected, failed, triune_triggered=false.

- [ ] Step 1: Write failing tests:
  - test_suricata_ingest_drains_only_new_pending_alerts
  - test_suricata_ingest_repeat_does_not_duplicate_world_event
  - test_suricata_ingest_historical_alerts_are_not_backfilled
  - test_suricata_ingest_projection_failure_leaves_retryable_state
  - test_suricata_ingest_promoted_observation_triggers_triune

- [ ] Step 2: Verify RED.
- [ ] Step 3: Modify only the existing Suricata ingest route after native VNS ingestion. Do not touch Zeek, VNS stats, Suricata flow mapping, DNS mapping/correlation, alert parsing/source claim, or authority rails.
- [ ] Step 4: Verify focused suite GREEN:

~~~bash
PYTHONPATH=. python -m pytest -q   backend/tests/test_observation_fabric.py   backend/tests/test_suricata_observation_bridge.py
~~~

- [ ] Step 5: Syntax gate:

~~~bash
python -m py_compile   backend/services/observation_fabric.py   backend/services/world_events.py   backend/routers/advanced.py
~~~

- [ ] Step 6: Recreate backend only using the already-proven compose stack. Wait for /api/health and run the existing explicit Suricata ingest endpoint.

Acceptance:
- native record_errors=0
- observation_fabric.failed=0
- observation_fabric.triune_triggered=false
- no historical flood

- [ ] Step 7: Mongo exact-once proof:

~~~text
canonical observation docs == unique observation_id
observation_promoted world-event docs == unique payload.observation_id
historical unmarked Suricata evidence remains unpromoted
~~~

Inspect one projected alert entity and prove native signature/category/severity and witness survive. No fabricated ATT&CK ID or strategic risk.

- [ ] Step 8: Backend-death replay proof. Force-recreate again, rerun ingest, and prove old observations/world events do not duplicate while repeated unchanged material evidence is retained without another world event.

- [ ] Step 9: Final regression gate:

~~~bash
PYTHONPATH=. python -m pytest -q   backend/tests/test_observation_fabric.py   backend/tests/test_suricata_observation_bridge.py

PYTHONPATH=. python -m pytest -q   authority_tests/test_seraph_authority_chain.py   --confcutdir=authority_tests
~~~

- [ ] Step 10: Commit: feat: promote Suricata observations into canonical world state

## Completion Contract

This plan earns PASS only when fresh evidence proves:

~~~text
Suricata durable alert evidence                  PASS
canonical observation identity                   PASS
restart-safe observation claim                   PASS
material-change promotion                        PASS
repeat-without-change suppression                PASS
canonical alert entity projection                PASS
world-event exact-once projection                PASS
Triune trigger policy for promoted observations   PASS
historical evidence not backfilled               PASS
Mongo indexes source-controlled                  PASS
authority regression                             PASS
~~~

Not claimed by this plan:

~~~text
world-manifold/hash mutation                     NOT IN THIS PLAN
cross-witness reconciliation                     NOT IN THIS PLAN
Hunting local/remote correlation                 NOT IN THIS PLAN
Harmonic evidence consumption                    NOT IN THIS PLAN
Chorus evidence-participant coherence            NOT IN THIS PLAN
continuous ingestion                             NOT IN THIS PLAN
WireGuard governed topology                      NOT IN THIS PLAN
Phase H full symphony                            NOT IN THIS PLAN
~~~
