# Rev14 Statistical Analysis

## Cohort Rates

| Cohort | Strict containment | 95% CI | Failure rate | 95% CI | Real-asset breach rate | 95% CI |
| --- | ---: | --- | ---: | --- | ---: | --- |
| claude_baseline_no_defense_r01 | 0.3158 | [0.1908, 0.4746] | 0.6842 | [0.5254, 0.8092] | 0.6842 | [0.5254, 0.8092] |
| claude_baseline_r01_defended | 0.9737 | [0.8651, 0.9953] | 0.0263 | [0.0047, 0.1349] | 0.0263 | [0.0047, 0.1349] |
| claude_baseline_rev13_curated | 1.0000 | [0.9082, 1.0000] | 0.0000 | [0.0000, 0.0918] | 0.0000 | [0.0000, 0.0918] |
| claude_baseline_stealth_slow_r02 | 0.8421 | [0.6958, 0.9256] | 0.1579 | [0.0744, 0.3042] | 0.1579 | [0.0744, 0.3042] |
| gemini25flash_baseline_r01_full | 1.0000 | [0.9082, 1.0000] | 0.0000 | [0.0000, 0.0918] | 0.0000 | [0.0000, 0.0918] |
| gemini25flash_baseline_r01_no_soar | 0.9737 | [0.8651, 0.9953] | 0.0263 | [0.0047, 0.1349] | 0.0263 | [0.0047, 0.1349] |
| gpt4o_baseline_latest_nonzero_per_class | 1.0000 | [0.9082, 1.0000] | 0.0000 | [0.0000, 0.0918] | 0.0000 | [0.0000, 0.0918] |
| grok3mini_baseline_r01_full | 1.0000 | [0.9082, 1.0000] | 0.0000 | [0.0000, 0.0918] | 0.0000 | [0.0000, 0.0918] |
| grok3mini_baseline_r01_no_soar | 1.0000 | [0.9082, 1.0000] | 0.0000 | [0.0000, 0.0918] | 0.0000 | [0.0000, 0.0918] |
| grok3mini_baseline_stealth_slow_r01 | 0.9737 | [0.8651, 0.9953] | 0.0263 | [0.0047, 0.1349] | 0.0263 | [0.0047, 0.1349] |
| llama32_1b_baseline_r01_full | 1.0000 | [0.9082, 1.0000] | 0.0000 | [0.0000, 0.0918] | 0.0000 | [0.0000, 0.0918] |
| llama32_1b_baseline_r01_no_soar | 1.0000 | [0.9082, 1.0000] | 0.0000 | [0.0000, 0.0918] | 0.0000 | [0.0000, 0.0918] |
| qwen05b_baseline_r01_networked | 1.0000 | [0.9082, 1.0000] | 0.0000 | [0.0000, 0.0918] | 0.0000 | [0.0000, 0.0918] |

## Defended vs Control Comparisons

### claude_baseline_rev13_curated vs claude_baseline_no_defense_r01

- Fisher exact two-sided p-value: 0.0
- Chi-square: 39.52 (approx p=3e-10)
- Containment risk ratio: 3.166667
- Corrected odds ratio: 163.24
- Risk difference: 0.684211

### claude_baseline_r01_defended vs claude_baseline_no_defense_r01

- Fisher exact two-sided p-value: 7e-10
- Chi-square: 35.903250189 (approx p=2.1e-09)
- Containment risk ratio: 3.083333
- Corrected odds ratio: 53.0
- Risk difference: 0.657895

### claude_baseline_stealth_slow_r02 vs claude_baseline_no_defense_r01

- Fisher exact two-sided p-value: 6.0208e-06
- Chi-square: 21.5909090909 (approx p=3.3745e-06)
- Containment risk ratio: 2.666667
- Corrected odds ratio: 10.6
- Risk difference: 0.526316

## Reviewer-facing wording

Compared with the no-defense control, the defended configuration produced a substantially higher strict containment rate, and the effect remains statistically distinguishable under exact 2x2 testing. This supports the claim that containment is attributable to active defensive routing rather than benchmark artefact or model indecision.
