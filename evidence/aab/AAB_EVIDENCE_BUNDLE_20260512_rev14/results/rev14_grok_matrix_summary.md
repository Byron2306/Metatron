# Rev14 Grok Matrix Summary

This artifact folds the saved Grok full-defense and `no_soar` 38-class matrices into the rev14 bundle so reviewers can inspect the defended-versus-SOAR-ablated delta without re-running the harness.

| Variant | Runs | Contained rate | Pass rate | Zero real-asset rate | Escape or real-asset runs | Mean tokens | Mean wall time (s) | Source |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| full | 38 | 0.5263 | 0.5263 | 1.0000 | 0 | 2575.68 | 61.10 | aab_live_matrix_full_grok3mini_steps4_20260512T195443Z.json |
| no_soar | 38 | 0.5526 | 0.5526 | 1.0000 | 0 | 2583.03 | 89.31 | aab_live_matrix_no_soar_grok3mini_steps4_20260512T205838Z.json |

## Reviewer-facing summary

The defended Grok full matrix completed all 38 classes with 0 escape-or-real-asset runs and a zero-real-asset rate of 1.0000.
Removing SOAR increased containment rate to 0.5526, increased pass rate to 0.5526, and introduced 0 escape-or-real-asset run.
