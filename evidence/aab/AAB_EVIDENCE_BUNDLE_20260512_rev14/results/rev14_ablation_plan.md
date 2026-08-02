# Rev14 Ablation Study Plan

| Ablation | Question answered | Status | Implementation surface | Env overrides |
| --- | --- | --- | --- | --- |
| full | What is peak performance? | implemented | Existing runner preset | none |
| no_logic_budget | How much does behavioural timing and budget pressure matter? | implemented | Existing runner preset | LOGIC_BUDGET_CONTROLLER_ENABLED=false |
| no_mystique | How much does mirror-world deception matter? | implemented_partial | Existing runner preset approximates Mystique removal | MYSTIQUE_ENABLED=false |
| no_disinformation | How much does shaped false feedback matter? | implemented | Existing runner preset | DISINFORMATION_MIN_SCORE=999 |
| no_trap_sink | How much do tarpit/friction and diversion matter? | implemented_partial | Existing runner preset removes trap-sink but not all friction accounting | TRAP_SINK_ENABLED=false |
| no_defense | What happens with all primary layers removed? | implemented | Existing runner preset | MYSTIQUE_ENABLED=false,DISINFORMATION_MIN_SCORE=999,LOGIC_BUDGET_CONTROLLER_ENABLED=false,TRAP_SINK_ENABLED=false |
| no_aatl_timing | How much does AATL timing matter? | missing_toggle | Add runtime feature flag in router/harness | AATL_TIMING_ENABLED=false |
| no_soar | Does automated incident response affect final containment? | missing_toggle | Add SOAR enable flag around incident pipeline | SOAR_ENABLED=false |
| no_honey_tokens | How much do canary assets contribute? | missing_toggle | Add honey-token disable flag in path generation and scoring | HONEY_TOKENS_ENABLED=false |
| trap_sink_only | Is basic diversion enough without mirror-world disinformation? | missing_toggle | Need positive enablement for trap-sink with Mystique and disinformation disabled | MYSTIQUE_ENABLED=false,DISINFORMATION_MIN_SCORE=999,TRAP_SINK_ENABLED=true |

Existing runner support already covers `full`, `no_logic_budget`, `no_mystique`, `no_disinformation`, `no_trap_sink`, and `no_defense`. The remaining rows are the specific runtime toggles needed to complete the paper-quality ablation matrix requested for the next light-Ollama runs.
