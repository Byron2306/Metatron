# MITRE Coverage Evidence Report

- Generated: 2026-03-16T06:53:28.700006+00:00
- Base URL: `http://127.0.0.1:8011/api`

## Profile Metrics

| Metric | strict | balanced | hardened |
|---|---:|---:|---:|
| coverage_percent_gte2 | 81.94 | 81.94 | 81.94 |
| coverage_percent_gte3 | 71.3 | 81.48 | 81.48 |
| coverage_percent_gte4 | 27.78 | 61.57 | 61.57 |
| covered_score_gte3 | 214 | 259 | 259 |
| covered_score_gte4 | 75 | 216 | 216 |
| enterprise_parents_gte3 | 154 | 176 | 176 |
| enterprise_parents_gte4 | 60 | 133 | 133 |

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
| `implementation_depth_validated` | True | 26 | 26 | 0 |
| `priority_gap_implementation_depth` | True | 0 | 0 | 0 |
| `corroborated_catalog` | True | 27 | 0 | 27 |
| `multi_plane_capability_chain` | True | 23 | 0 | 23 |
| `priority_gap_operational_chain` | True | 0 | 0 | 0 |
| `hardened_enterprise_score4` | True | 91 | 0 | 91 |
| `operational_validation_chain` | True | 0 | 0 | 0 |

## Delta Summary

```json
{
  "strict_to_balanced": {
    "changed_techniques": 160,
    "promoted_to_gte3": 45,
    "promoted_to_gte4": 141,
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
        "technique": "T1069",
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
        "technique": "T1547",
        "from_score": 3,
        "to_score": 4,
        "delta": 1,
        "sources_after": [
          "atomic_job",
          "code_sweep",
          "evidence_fusion_corroborated",
          "hardened_enterprise_validated",
          "osquery",
          "timeline_mitre_catalog"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 12
      },
      {
        "technique": "T1027",
        "from_score": 3,
        "to_score": 4,
        "delta": 1,
        "sources_after": [
          "atomic_job",
          "code_sweep",
          "evidence_fusion_corroborated",
          "hardened_enterprise_validated",
          "osquery",
          "threat_actor_catalog",
          "timeline_mitre_catalog"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 10
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
        "technique": "T1082",
        "from_score": 3,
        "to_score": 4,
        "delta": 1,
        "sources_after": [
          "code_sweep",
          "evidence_fusion_corroborated",
          "hardened_enterprise_validated",
          "soar_mapping_catalog",
          "threat_hunting_ruleset",
          "timeline_mitre_catalog"
        ],
        "operational_evidence_after": true,
        "implemented_evidence_count_after": 8
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
    "strict_gte3": 71.3,
    "balanced_gte3": 81.48,
    "balanced_gte4": 61.57,
    "hardened_gte4": 61.57
  }
}
```

_Interpretation_: strict disables inferred/promotion passes; balanced enables operational/corroboration passes; hardened additionally requires strong JWT + Trivy prerequisites.
