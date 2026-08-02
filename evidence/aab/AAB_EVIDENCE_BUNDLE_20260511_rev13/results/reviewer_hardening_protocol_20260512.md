# AAB Reviewer-Hardening Protocol (2026-05-12)

This addendum records the next experimental design steps needed for stronger external claims. Rev13 remains a single-model, full-defense containment sweep; the steps below quantify causal effect, false positives, and uncertainty.

## 1. No-defense and reduced-defense baselines

Run the same 38 classes with defensive ablations and compare against `full`:

```bash
# reduced defense examples
python run_live_aab.py --all --ablation no_mystique --matrix --repeats 3 --save --summary-label reduced_no_mystique
python run_live_aab.py --all --ablation no_disinformation --matrix --repeats 3 --save --summary-label reduced_no_disinformation
python run_live_aab.py --all --ablation no_logic_budget --matrix --repeats 3 --save --summary-label reduced_no_logic_budget
python run_live_aab.py --all --ablation no_trap_sink --matrix --repeats 3 --save --summary-label reduced_no_trap_sink

# combined no-defense baseline
python run_live_aab.py --all --ablation no_defense --matrix --repeats 3 --save --summary-label no_defense_r3
```

The `no_defense` preset disables Mystique, disinformation routing, logic-budget friction, and trap-sink routing together. Rev13 does not yet claim that causal delta because this baseline has not been run.

## 2. Cross-model replications

```bash
python run_live_aab.py --all --models gpt-4o,claude-sonnet-4-5-20250929 --matrix --repeats 3 --save --summary-label cross_model_r3
```

Add open-weight endpoints through the same `AAB_LIVE_MODEL`/provider adapter before making model-general claims.

## 3. Transcript vs verification layers

Use separate tables:

- `transcript_layer_summary_20260512.csv`: LLM-decision/transcript view.
- `route_layer_verification_20260512.csv`: authoritative action/router verification view with per-action route, delay, score, asset taxonomy, and real/honey flags.

## 4. Strict JSON compatibility

Non-finite `Infinity` CBR/TBCR values are normalized to the label `infinite_zero_real_asset` in the bundle JSON evidence. This preserves meaning while remaining strict JSON-compatible.

## 5. Confidence intervals

Use `--repeats N --matrix`; `run_live_aab.py` already emits CI summaries through `_summarize_rows()`. For publication-grade claims, use at least 3 repeats for smoke confidence and 5+ repeats for class-level CIs.

## 6. Asset taxonomy

Use `asset_taxonomy_20260512.json`/`.md` to distinguish sentinel real assets, honey surfaces, sentinel-adjacent probes, and synthetic/instrumented surfaces.

## 7. Benign controls

```bash
python run_live_aab.py --benign-controls --save
```

This estimates false-positive routing against health checks, docs crawling, and normal admin/API usage.

## 8. Minimal replay harness

Run the offline replay harness without API keys:

```bash
python evidence/aab/AAB_EVIDENCE_BUNDLE_20260511_rev13/source/minimal_replay_harness.py \
  --bundle evidence/aab/AAB_EVIDENCE_BUNDLE_20260511_rev13
```

It validates strict JSON parsing, recomputes route/action totals from canonical evidence, and checks the zero-real-asset containment claim.
