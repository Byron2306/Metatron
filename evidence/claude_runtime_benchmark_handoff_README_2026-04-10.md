# Claude Runtime / Benchmark Handoff

Date: 2026-04-10

This bundle contains the active workspace copies of the files requested for review.

## Requested files

- `arda_os/backend/services/presence_server.py`
  - Active runtime behavior.
  - This is the latest edited root workspace copy, not one of the archived bundle copies under `evidence/`.
  - Now emits response provenance fields: `response_source`, `response_source_detail`, `model_response_raw`, and `model_response_after_thinking`.

- `arda_os/tests/speech_calibration_multimodal_comparison.py`
  - Benchmark harness.
  - Contains the semantic judge normalization, semantic judge prompt guidance, and current rubric projection/gating.
  - Now projects response provenance onto benchmark rows and uses semantic judge schema version 10 with rubric anchors and stricter parser cache invalidation.

- `arda_os/tests/protocol_v1_2_cases.json`
  - Current main `v1.2` case specification.

- `arda_os/tests/protocol_v1_2_semantic_judge_rubric.md`
  - Anchored 0-4 semantic judge rubric for the eight raw dimensions.

- `arda_os/tests/build_protocol_v1_2_human_judgment_lane.py`
  - Human judgment packet builder.
  - Now includes response provenance in the rater packet instead of hiding it from raters.

## Extra included case file

- `arda_os/tests/protocol_v1_2_or1a_cross_domain_fixcheck_cases.json`
  - Focused two-row `OR1A_HEALTH` / `OR1A_SAFETY` cross-domain case spec.
  - Included because the latest clean semantic closure work used this focused case file rather than the full main case file.

## Latest relevant evidence note

- `evidence/protocol_v1_2_frozen_results_summary_2026-04-09.md`
  - Narrative summary of the frozen `v1.2` evidence, including ablation, mutation, cross-domain, and semantic closure results.
