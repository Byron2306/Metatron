# Seraph Symphonic Evidence Fabric — Design Specification

**Date:** 2026-10-08  
**Repo:** `Byron2306/Metatron`  
**Branch:** `rescue/pre-purge-2026-10-03`

## Purpose

Complete the semantic bridge between Seraph's proven sensor/evidence rails and its proven authority/execution rails without regressing working code.

The target is a governed, contradiction-preserving security fabric where independent sensors produce durable evidence, reconciled observations alter canonical world state, Harmonic/Polyphonic Governance interprets coherence and discord, and capability-bound execution settles back into proof.

## Core invariant

```text
NO VALID CAPABILITY
→ NO TOOL EXECUTION
```

Vector Memory may inform later reasoning but must never become authority.

## Proven baseline

### Authority and execution

The following are treated as protected unless a regression proves otherwise:

- canonical MCP authority in `backend/services/mcp_server.py`
- Token Broker principal/audience/action/target/tool binding
- replay refusal
- Tool Gateway final PEP
- parent → child capability delegation
- delegation receipts and settlement
- Chorus missing-participant truth
- existing Harmonic feedback framework

### Unified Agent

- 29 monitor surfaces proven
- monolithic canonical telemetry writer
- no Docker socket in the Agent
- auto remediation disabled
- VPN auto configuration disabled
- Falco disabled by policy

### Integration fabric

The canonical registry contains 18 integration identities with explicit role, family and lifecycle semantics.

Representative roles:

- Zeek: network truth
- Suricata: IDS/classification
- Arkime: packet/session provenance
- YARA: artifact pattern detection
- Trivy: vulnerability posture
- osquery: endpoint query
- Velociraptor: endpoint hunting/forensics
- Volatility: memory forensics
- BloodHound: identity attack graph
- Sigma: detection semantics
- Atomic Red Team / PurpleSharp: governed validation stimulus
- Docker posture: container runtime posture

## Proven Phase 4 work

### Phase 4A

Typed world-evidence rails exist:

- `integration_evidence_observed`
- `endpoint_evidence_observed`

Initial fan-out uses `trigger_triune=False` to avoid strategic recomputation on low-level telemetry churn.

### Phase 4B.1 Zeek

Locked PASS unless an actual regression appears:

```text
Zeek actual traffic
→ native VNS flow/DNS
→ Mongo persistence
```

Established facts:

- `/vns/stats` reports state and is not an ingestion trigger.
- The canonical VNS singleton is the running `services.vns.vns` instance.
- A standalone Python process does not prove the running FastAPI singleton state.
- Zeek parsing must preserve its real header/schema contract.

### Phase 4B.2 Suricata

Locked PASS unless an actual regression appears:

```text
Suricata flow
→ VNS flow
→ Mongo
→ restart-safe source identity

Suricata DNS
→ request/response correlation
→ correct client attribution
→ VNS DNS
→ Mongo
→ restart-safe source identity

Suricata alert
→ typed alert evidence
→ Mongo
→ restart-safe source identity
```

Alerts are not fabricated into flows.

Durable identity is source-native `source_event_id`.

Latest decisive runtime proof:

```text
FLOW DOCS   = FLOW UNIQUE
DNS DOCS    = DNS UNIQUE
```

after backend restart.

The local working tree currently has a `world_fanout_status="pending"` marker on new Suricata alert evidence, but canonical alert promotion to world state is not yet runtime-proven.

## Central architectural problem

The execution hand is strong. The sensory ears are becoming real. The missing organ is the semantic nervous system between durable observation and governed cognition.

Target dataflow:

```text
source-native evidence
        ↓
durable identity
        ↓
canonical observation envelope
        ↓
reconciliation / correlation
        ↓
promotion policy
        ↓
canonical world event
        ↓
world model / world manifold
        ↓
Hunting / ML / AATL / AATR / CCE
        ↓
Metatron / Michael / Loki
        ↓
Harmonic / Polyphonic Governance
        ↓
Chorus
        ↓
Outbound Gate / Notation / Token Broker
        ↓
MCP / Tool Gateway / SOAR / Unified Agent
        ↓
actual-effect proof
        ↓
world-state settlement
```

Raw evidence must not be equated with a strategic world-state change.

## Design principles

### Preserve independent voices

```text
sensor observation
≠ analytic interpretation
≠ governance decision
≠ execution authority
```

Zeek, Suricata, Arkime, Agent telemetry, YARA, osquery, Trivy, Volatility and later integrations retain witness provenance.

Agreement is corroboration. Disagreement is evidence.

### Durable identity before fan-out

Any source-native event that can replay after process death must have durable identity before influencing downstream state.

Restart must not duplicate canonical observations or world events.

### Observation is not promotion

A canonical observation means:

> A named witness observed this fact or classification at this time.

A world event means:

> This observation materially changes Seraph's model of the current world.

Promotion is therefore a first-class policy boundary.

### No second Harmonic framework

Existing Harmonic, edge-mesh, domain-pulse, policy, Chorus and governance machinery must be reused.

### No fabricated choir

Chorus only records participants that actually participated.

Missing expected witnesses, contradictory evidence, incorrect sequence and missing governance participants remain visible.

### Evidence before completion claims

PASS requires fresh evidence appropriate to the seam:

- RED before GREEN for behavior changes
- focused automated tests
- restart test where durability matters
- live API/runtime proof
- Mongo durability/uniqueness proof
- authority regression suite when authority paths are touched

## Canonical observation envelope

Introduce one normalized observation contract between source-native persistence and world-state promotion.

Minimum fields:

```text
schema
observation_id
witness
source_kind
source_event_type
source_event_id
observed_at
ingested_at
entity_refs
reconciliation_scope
native_severity
native_confidence
provenance
evidence_digest
payload
promotion_state
```

Requirements:

- preserve source-native `source_event_id`
- deterministic evidence digest
- never erase `witness`
- do not silently turn native severity/confidence into strategic risk
- distinguish at least `pending`, `promoted`, `reconciled`, `suppressed_as_duplicate`, `retained_without_promotion`
- historical evidence is not retroactively promoted merely because promotion code is deployed

## Promotion policy

Initial material-change classes:

1. Novel material observation
2. Independent corroboration
3. Material contradiction
4. Escalation in severity/confidence/entities/consequence
5. Resolution of a previously material condition

Repeated IDS alerts that do not change world understanding remain durable evidence but do not each become strategic world events.

Triune recomputation remains disabled during initial rollout.

## World-state projection

Persisting `world_events` is not proof that canonical world state changed.

We must prove:

```text
promoted observation
→ canonical world_event
→ world entity/edge/manifold mutation
→ changed world-state reference/hash where appropriate
```

Reuse the existing `WorldModelService` and `WorldManifoldService` seams.

Replay of the same source event must not mutate canonical state again.

## Cross-witness reconciliation

Initial network voices:

- Zeek flow/DNS
- Suricata flow/DNS/alert classification
- Arkime session provenance
- Unified Agent endpoint observation when available

A neutral reconciliation key must preserve source semantics rather than pretending all tools emit the same shape.

Reconciliation outputs must represent:

```text
corroborated
contradicted
single_witness
expected_witness_missing
temporally_ambiguous
```

## Hunting correlation

`ThreatHuntingEngine.hunt_network()` expects local/remote semantics.

Zeek and Suricata provide source/destination semantics.

Before feeding those sources into Hunting, define or reuse an explicit network-zone/direction adapter.

Never map destination to remote blindly.

Hunting remains an independent analytic witness and cannot overwrite source-native classification.

## Continuous ingestion

Manual curls and dashboard-triggered ingestion are proof mechanisms, not the production sensory loop.

The bounded ingestion service/scheduler must:

- ingest Zeek and Suricata on a controlled cadence
- preserve durable identity
- support backpressure
- expose lag/errors
- restart without replay storms
- avoid mutating state from dashboard reads
- be cleanly disabled for tests/maintenance

## Integration rollout

After Zeek/Suricata/Arkime prove the contract, reuse it for:

1. osquery / Fleet
2. YARA
3. ClamAV
4. Trivy
5. Volatility
6. Velociraptor
7. Sigma

Atomic Red Team and PurpleSharp are stimulus producers, not ordinary observation witnesses.

## Harmonic and Chorus bridge

Reconciled world-state changes feed the existing Harmonic system.

Harmonic should reason over:

- corroboration density
- contradiction
- source diversity
- missing expected witnesses
- timing/sequence
- world-state drift
- execution settlement

Chorus should eventually score evidence participation as well as execution participation.

## WireGuard gate

WireGuard remains deferred until topology changes can be independently verified.

VPN PASS requires:

```text
governed capability
→ SOAR / Agent transition
→ actual host route/interface change
→ Agent observation
+ independent VNS observation
→ Chorus settlement
→ Harmonic feedback
→ rollback proof
```

No kill switch before rollback and internet/DNS/backend continuity are proven.

## Database and deployment invariants

Mongo uniqueness/index guarantees introduced during Phase 4 must become source-controlled startup behavior.

A fresh deployment must recreate the same constraints without manual shell repair.

Correctness-critical persistence must not silently swallow database failures.

## Non-regression boundaries

Protected by default:

- canonical MCP singleton
- Token Broker semantics
- MCP audience/tool binding and replay refusal
- Tool Gateway final PEP
- delegation receipts/settlement
- Chorus missing-participant truth
- existing Harmonic framework
- Unified Agent 29-surface census
- no Docker socket in Unified Agent
- Zeek VNS semantics
- Suricata flow/DNS/alert separation
- Suricata restart-safe source identity
- Falco disabled by policy
- VPN auto configuration disabled

No unrelated refactors during this implementation.

## Implementation sequence

### Stage 1: Observation contract

Freeze canonical schema and durable DB invariants.

### Stage 2: Suricata promotion

Only newly admitted durable alert evidence enters promotion. Add material-change policy and crash-safe outbox semantics. Prove restart does not replay world events.

### Stage 3: World-state mutation

Route promoted observations through canonical world events and prove exact-once entity/edge/manifold impact.

### Stage 4: Hunting semantics

Define network-zone adapter and preserve independent Hunting output.

### Stage 5: Arkime reconciliation

Normalize session provenance and reconcile Zeek + Suricata + Arkime without flattening witnesses.

### Stage 6: General integration adapters

Roll the contract to osquery/Fleet, YARA, ClamAV, Trivy, Volatility, Velociraptor and Sigma.

### Stage 7: Harmonic + Chorus evidence bridge

Feed reconciled evidence through existing Harmonic edge/domain mechanisms and extend Chorus evidence-participant coherence.

### Stage 8: Governed WireGuard topology

Capability-bound transition, independent verification, rollback, Chorus/Harmonic settlement.

### Stage 9: Controlled Phase H incident

```text
controlled stimulus
→ independent sensors
→ canonical observations
→ reconciliation
→ world state
→ cognition
→ Metatron / Michael / Loki
→ Harmonic / Polyphonic Governance
→ Notation
→ capability
→ MCP
→ SOAR / Agent
→ actual effect
→ receipt
→ Chorus settlement
→ Harmonic feedback
→ TVR / PQ proof
→ world-state feedback
```

## Acceptance criteria

Phase H is not ready until:

- independent witnesses survive process death without replay
- duplicate source events do not duplicate observations/world events
- raw evidence volume cannot trigger uncontrolled strategic recomputation
- witness provenance survives every normalization step
- contradiction remains first-class
- promotion demonstrably changes canonical world state when appropriate
- Hunting, Harmonic and Chorus consume evidence through explicit interfaces
- authority remains capability-bound
- a completed SOAR job is not accepted as real-effect proof without downstream evidence
- fresh deployments recreate DB uniqueness guarantees automatically
- authority regression tests remain green after authority-touching changes

## Known gaps outside immediate scope

- telemetry chain is tamper-evident but not fully durable immutable append-only storage
- Vector Memory is advisory and not production-durable
- capability delegation is fail-closed but not yet proven concurrency-atomic
- strict canonical UTC serialization should replace generic `default=str`
- legacy Agent auth rails still need later cleanup
- known false positives need calibration after plumbing stabilizes
- TPM/ARDA hardware-rooted identity and peer membership remain later gates
