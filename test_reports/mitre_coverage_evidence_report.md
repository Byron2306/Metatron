# MITRE Coverage Evidence Report

- Generated: 2026-03-16T18:01:05.340074+00:00
- Base URL: `http://127.0.0.1:8051/api`

## Profile Metrics

| Metric | strict | balanced | hardened |
|---|---:|---:|---:|
| coverage_percent_gte2 | 92.13 | 92.13 | 92.13 |
| coverage_percent_gte3 | 81.94 | 91.67 | 91.67 |
| coverage_percent_gte4 | 39.81 | 71.76 | 71.76 |
| covered_score_gte3 | 240 | 284 | 284 |
| covered_score_gte4 | 105 | 241 | 241 |
| enterprise_parents_gte3 | 177 | 198 | 198 |
| enterprise_parents_gte4 | 86 | 155 | 155 |

## Hardened Prerequisites

```json
{
  "jwt_secret_strong": true,
  "trivy_available": true,
  "hardened_mode_ready": true
}
```

## Scoring Pass Trace (hardened profile request)

| Pass | Enabled | Changed | Promoted >=3 | Promoted >=4 |
|---|---|---:|---:|---:|
| `implementation_depth_validated` | True | 25 | 25 | 0 |
| `priority_gap_implementation_depth` | True | 0 | 0 | 0 |
| `corroborated_catalog` | True | 20 | 0 | 20 |
| `multi_plane_capability_chain` | True | 24 | 0 | 24 |
| `priority_gap_operational_chain` | True | 0 | 0 | 0 |
| `hardened_enterprise_score4` | True | 92 | 0 | 92 |
| `operational_validation_chain` | True | 0 | 0 | 0 |

## Delta Summary

```json
{
  "strict_to_balanced": {
    "changed_techniques": 155,
    "promoted_to_gte3": 44,
    "promoted_to_gte4": 136,
    "regressed_techniques": 0,
    "top_changes": [
      {
        "technique": "T1056.001",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 5
      },
      {
        "technique": "T1553",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 3
      },
      {
        "technique": "T1556",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 3
      },
      {
        "technique": "T1003.005",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1055.001",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1078.003",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1110.001",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1127.001",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1134.001",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1200",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "evidence_fusion_corroborated",
          "hardened_enterprise_validated",
          "implementation_depth_validated",
          "osquery"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1222",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1484",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1497",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1538",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1542.002",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1547.006",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1553.002",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1558.002",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1563",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1564",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1574",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1574.001",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1574.006",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1592.002",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1601.001",
        "from_score": 2,
        "to_score": 4,
        "delta": 2,
        "sources_after": [
          "code_sweep",
          "hardened_enterprise_validated",
          "implementation_depth_validated"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 2
      },
      {
        "technique": "T1557",
        "from_score": 3,
        "to_score": 4,
        "delta": 1,
        "sources_after": [
          "browser_ssl_validation_capability",
          "code_sweep",
          "cspm_scanner_catalog",
          "evidence_fusion_multi_plane_capability",
          "hardened_enterprise_validated",
          "mobile_threat_detection_capability",
          "monitor_mobile_security_capability_catalog",
          "threat_actor_catalog"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 9
      },
      {
        "technique": "T1566",
        "from_score": 3,
        "to_score": 4,
        "delta": 1,
        "sources_after": [
          "code_sweep",
          "email_protection_capability_phishing",
          "evidence_fusion_corroborated",
          "hardened_enterprise_validated",
          "monitor_email_protection_capability_catalog",
          "threat_actor_catalog",
          "threat_intel",
          "timeline_mitre_catalog"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 8
      },
      {
        "technique": "T1021.001",
        "from_score": 3,
        "to_score": 4,
        "delta": 1,
        "sources_after": [
          "code_sweep",
          "cspm_scanner_catalog",
          "evidence_fusion_corroborated",
          "hardened_enterprise_validated",
          "monitor_cli_telemetry_capability_catalog",
          "threat_actor_catalog",
          "threat_hunting_ruleset",
          "threat_intel"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 7
      },
      {
        "technique": "T1113",
        "from_score": 3,
        "to_score": 4,
        "delta": 1,
        "sources_after": [
          "code_sweep",
          "evidence_fusion_corroborated",
          "hardened_enterprise_validated",
          "hypothesis_capability_catalog",
          "priority_gap_implementation_depth",
          "priority_gap_operational_chain",
          "threat_hunting_ruleset",
          "timeline_mitre_catalog"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 7
      },
      {
        "technique": "T1530",
        "from_score": 3,
        "to_score": 4,
        "delta": 1,
        "sources_after": [
          "code_sweep",
          "cspm_scanner_catalog",
          "evidence_fusion_multi_plane_capability",
          "hardened_enterprise_validated",
          "hypothesis_capability_catalog",
          "priority_gap_implementation_depth",
          "priority_gap_operational_chain",
          "sigma"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 7
      }
    ]
  },
  "balanced_to_hardened": {
    "changed_techniques": 0,
    "promoted_to_gte3": 0,
    "promoted_to_gte4": 0,
    "regressed_techniques": 0,
    "top_changes": []
  }
}
```

## Assertions

```json
{
  "balanced_gte3_not_lower_than_strict": true,
  "hardened_prerequisites_ready": true,
  "hardened_gte4_not_lower_than_balanced": true,
  "summary": {
    "strict_gte3": 81.94,
    "balanced_gte3": 91.67,
    "balanced_gte4": 71.76,
    "hardened_gte4": 71.76
  }
}
```

_Interpretation_: strict disables inferred/promotion passes; balanced enables operational/corroboration passes; hardened additionally requires strong JWT + Trivy prerequisites.
