# DIO-5 verification and runtime handoff

The code for the six-task observation-core plan is implemented. Overall PASS
is withheld: deployed ingest, live Mongo uniqueness, and backend-death replay
must still run on the existing Debian stack. DIO-5 stays In Progress.

## Verified code gates

- 44 focused observation/Suricata tests pass, including the real native EVE
  reader and ingest route with Mongo-shaped test fixtures.
- 6 authority-chain tests pass.
- Modified production Python modules compile and `git diff --check` passes.
- All new behavioral changes were preceded by observed failing tests.
- The independent whole-branch review found two Important races, both fixed
  with deterministic RED→GREEN regressions: duplicate decision poisoning and
  older failed projection overwriting a newer native severity.

Test commands from the repository root, using the operator's Python environment:

```bash
python -m pip install -r backend/tests/requirements-observation.txt
PYTHONPATH=. python -m pytest -q backend/tests/test_observation_fabric.py backend/tests/test_suricata_observation_bridge.py
PYTHONPATH=. python -m pytest -q authority_tests/test_seraph_authority_chain.py --confcutdir=authority_tests
```

Mongomock is a test dependency only. These tests do not certify Mongo server
concurrency or a running FastAPI singleton. Existing WorldModelService
Pydantic/UTC deprecation warnings remain outside this change's scope.

## Broader suite limitation

A bare `pytest -q` run stopped at three collection errors:

- `backend/tests/test_outbound_gate_and_snapshot.py`: missing `test_utils`.
- Archived `live_arda_fabric/evidence/live_recovery_rejoin_package_20260515T131336Z_with_tests/tests/free-claude-code/smoke`: missing `smoke`.
- That archive's `free-claude-code/tests`: missing `config.settings`.

No full-suite PASS is claimed. No unrelated test bootstrap was changed.

## Implementation rulings

- Correctness-critical indexes fail backend startup if uniqueness cannot be
  enforced. Cost: existing conflicting data/index definitions require operator
  inspection before rollout; they are not silently ignored.
- The world-model upsert seam accepts opt-in `recalculate_risk=False` and uses
  an explicit collection None guard. Cost: passive projection skips synthesized
  risk; legacy callers keep their risk-recalculation default. Governance hashes
  and manifold semantics are unchanged.
- Observation-owned alert entities have a partial unique ID index. Cost:
  conflicting observation entity IDs refuse startup rather than allowing races.
- Durable material revisions fence entity writes, so an older retry can finish
  its world event without replacing a newer entity classification. Cost: stale
  observation entity updates are refused; default upsert behavior is preserved.
- Live deployment and later evidence-fabric capabilities remain separate gates.
  Cost: this change does not certify runtime or implement Hunting, cross-witness
  reconciliation, Harmonic, Chorus, continuous ingestion, WireGuard or Phase H.

## Required operator runtime proof

1. Inspect the running `seraph-backend` Compose labels and bind mounts. Reuse
   its project, Compose files and environment. Point only its backend code bind
   mount at the DIO-5 worktree; preserve existing data and sensor mounts.
2. Recreate backend only. Wait for `/api/health`. Index failure is a refusal,
   not permission to drop indexes or delete evidence.
3. Invoke the existing authenticated `/api/advanced/vns/suricata/ingest` route.
   Require native `record_errors=0`, fabric `failed=0` and
   `triune_triggered=false`.
4. Count canonical observations against distinct `observation_id`; count
   `observation_promoted` events against distinct `payload.observation_id`.
   Require equality. Historical unmarked alert evidence must have no new
   observation linkage or promotion.
5. Inspect a projected alert: witness, native signature/category/severity,
   evidence digest and observed time survive; no synthesized ATT&CK or risk.
6. Recreate backend again and repeat ingest. Old evidence must not duplicate
   observations/events. A newly admitted unchanged alert must be retained;
   a material severity/category change must promote.
7. Rerun focused and authority gates. Only then record DIO-5 runtime PASS.

The pending canonical queue deliberately retries claims even after source
evidence has moved from pending to observed/reconciled. Failed persistence must
never be reported as emitted. Both decision and projection retries are durable.
