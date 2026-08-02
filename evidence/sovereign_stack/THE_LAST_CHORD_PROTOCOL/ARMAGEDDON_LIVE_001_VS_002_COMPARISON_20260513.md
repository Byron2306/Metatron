# Armageddon Live 001 vs 002 Comparison

## Verdict

Yes. `last_chord_armageddon_live_002` survived cleanly and is the reviewer-grade bundle.

Both Armageddon runs completed all 38 governed Last Chord child runs with zero recorded child-run failures, but `live_002` materially improves the evidence quality of the shared-stack background-noise layer. The difference is startup discipline, not child-run completion.

## Side-by-side summary

| Metric | live_001 | live_002 |
| --- | ---: | ---: |
| Group ID | `last_chord_armageddon_live_001` | `last_chord_armageddon_live_002` |
| Waves | 4 | 4 |
| Recorded child runs | 38 | 38 |
| Child runs with `returncode = 0` | 38 | 38 |
| Child runs with non-zero return code | 0 | 0 |
| Noise cycles | 315 | 674 |
| Noise events | 2835 | 6066 |
| Noise events with routing result | 0 | 6066 |
| Noise events with startup/network error | 2835 | 0 |
| Shared live URL | `http://127.0.0.1:8099` | `http://127.0.0.1:8099` |

## What changed

`live_001` proved that the 38-run wave harness could complete, but its early noise cycles were polluted by startup races. The noise entries in that bundle recorded repeated `Connection refused` errors for benign control traffic such as `/admin/dashboard`, `/health`, `/metrics`, and `/api/v1/export`.

`live_002` removed that weakness. The same benign controls were emitted only after the shared backend was ready, and the execution bundle records route outcomes like `pass_through` instead of connection failures. That makes `live_002` the stronger evidence package for concurrent shared-stack activity under noise.

## Interpretation

The survivability story is stable across both runs:

- all 38 governed child runs completed
- all 38 recorded `returncode = 0`
- the shared live stack stayed available long enough to service all wave traffic in `live_002`
- the difference between the bundles is evidence quality at the shared-noise layer, not the ability to finish the 38-run matrix

## Recommendation

Treat `live_001` as operationally successful but evidentially weaker. Treat `live_002` as the canonical Armageddon live bundle for downstream review, flattening, and markdown synthesis.
