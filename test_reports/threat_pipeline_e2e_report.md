# Threat Pipeline E2E Report

- Generated: 2026-03-16T06:53:28.213227+00:00
- Base URL: `http://127.0.0.1:8011/api`
- Total Steps: **73**
- Passed: **73**
- Failed: **0**
- Pass Rate: **100.0%**
- Avg Latency: **10.66 ms**

## Domain Summary

| Domain | Passed | Total | Pass Rate |
|---|---:|---:|---:|
| `ai_ml` | 4 | 4 | 100.0% |
| `analytics_reporting` | 2 | 2 | 100.0% |
| `cloud_cspm` | 1 | 1 | 100.0% |
| `container_security` | 1 | 1 | 100.0% |
| `core_auth` | 2 | 2 | 100.0% |
| `deception` | 6 | 6 | 100.0% |
| `email_web` | 3 | 3 | 100.0% |
| `endpoint_unified_agent` | 5 | 5 | 100.0% |
| `enterprise_policy` | 2 | 2 | 100.0% |
| `governance` | 9 | 9 | 100.0% |
| `hunting_correlation` | 1 | 1 | 100.0% |
| `mitre_posture` | 1 | 1 | 100.0% |
| `mobile_mdm` | 2 | 2 | 100.0% |
| `network_response` | 1 | 1 | 100.0% |
| `quantum_security` | 6 | 6 | 100.0% |
| `soar` | 1 | 1 | 100.0% |
| `stack_observability` | 13 | 13 | 100.0% |
| `threat_intel` | 1 | 1 | 100.0% |
| `threat_management` | 1 | 1 | 100.0% |
| `vpn` | 3 | 3 | 100.0% |
| `zero_trust` | 3 | 3 | 100.0% |

## Pipeline Artifacts

```json
{
  "user_email": "threat-e2e-b554a617@local",
  "threat_id": "1fbf2d94-2601-4363-b7e9-65f12c82c626",
  "aatl_response": {
    "session_id": "sess-128ddb40",
    "host_id": "finance-workstation-07",
    "timestamp": "2026-03-16T06:53:27.924005+00:00",
    "actor_type": "automated_script",
    "actor_confidence": 0.55,
    "machine_plausibility": 0.45,
    "human_plausibility": 0.55,
    "behavior_signature": {
      "command_velocity": 0.0,
      "avg_inter_command_delay": 0.0,
      "delay_variance": 0.0,
      "entropy_score": 4.461217285858332,
      "tool_switch_count": 0,
      "tool_switch_latency": 0.0,
      "retry_count": 0,
      "error_recovery_speed": 0.0,
      "parameter_mutation_rate": 0.0
    },
    "intent_accumulation": {
      "primary_intent": "reconnaissance",
      "confidence": 0.4,
      "supporting_intents": [
        "credential_access",
        "defense_evasion"
      ],
      "goal_convergence_score": 0.4
    },
    "lifecycle_stage": "reconnaissance",
    "threat_level": "low",
    "threat_score": 30.0,
    "recommended_strategy": "slow",
    "recommended_actions": [
      "throttle_commands",
      "inject_latency",
      "increase_logging"
    ],
    "indicators": [
      "fast_typing:0ms",
      "consistent_timing:variance=0ms"
    ]
  },
  "email_assessment_id": "email_dd5ae00bbd2c",
  "email_threat_score": 0.3,
  "browser_session_id": "iso_b12b25b543d9",
  "mobile_device_id": "mobile_d0f1237dd2da",
  "pending_before": 1,
  "agent_id": "e2e-agent-62c08a8d",
  "agent_auth_token_present": true,
  "decision_id": "4af0e45ca5c00465",
  "proposal_status": "queued_for_triune_approval",
  "pending_after": 2,
  "decision_present_in_pending": true,
  "approve_execution_summary": {
    "processed": 1,
    "executed": 1,
    "skipped": 0,
    "failed": 0
  },
  "executor_summary": {
    "processed": 0,
    "executed": 0,
    "skipped": 0,
    "failed": 0
  },
  "advanced_stack_snapshot": {
    "falco_available": false,
    "falco_alert_count": 0,
    "suricata_available": false,
    "zeek_available": false,
    "elasticsearch_connected": false,
    "kibana_configured": false,
    "sandbox_available": false,
    "yara_available": false
  },
  "correlation_summary": {
    "total": 2,
    "high_confidence": 0,
    "medium_confidence": 0,
    "low_confidence": 2,
    "no_correlation": 0
  },
  "timeline_count": 2,
  "audit_recent_count": 0,
  "mitre_snapshot": {
    "coverage_percent_gte3": 81.48,
    "covered_score_gte3": 259,
    "covered_score_gte4": 216,
    "observed_techniques": 299
  }
}
```

## Step Results

| Step | Result | HTTP | Latency (ms) | Details |
|---|---|---:|---:|---|
| `register_user` | PASS | 200 | 216.43 |  |
| `login_user` | PASS | 200 | 215.15 |  |
| `create_threat` | PASS | 200 | 3.34 |  |
| `aatl_analyze_cli_session` | PASS | 200 | 3.36 |  |
| `email_protection_analyze` | PASS | 200 | 8.76 |  |
| `browser_isolation_session_create` | PASS | 200 | 22.91 |  |
| `mobile_register_device` | PASS | 200 | 2.52 |  |
| `mobile_update_device_status` | PASS | 200 | 2.59 |  |
| `governance_pending_before` | PASS | 200 | 2.15 |  |
| `unified_agent_register` | PASS | 200 | 2.40 |  |
| `unified_agent_heartbeat` | PASS | 200 | 4.08 |  |
| `remediation_propose_block_ip` | PASS | 200 | 10.31 |  |
| `governance_pending_after` | PASS | 200 | 2.14 |  |
| `governance_approve_decision` | PASS | 200 | 3.76 |  |
| `governance_executor_run_once` | PASS | 200 | 2.17 |  |
| `threat_response_block_ip` | PASS | 200 | 5.38 |  |
| `governance_approve_e7149b8993f55687` | PASS | 200 | 11.40 |  |
| `zero_trust_register_device` | PASS | 200 | 2.56 |  |
| `zero_trust_evaluate_access` | PASS | 200 | 2.18 |  |
| `zero_trust_trust_score` | PASS | 200 | 1.95 |  |
| `vpn_add_peer` | PASS | 200 | 8.64 |  |
| `governance_approve_a978d27ab44274a0` | PASS | 200 | 5.39 |  |
| `vpn_start` | PASS | 200 | 9.38 |  |
| `governance_approve_5018c4178ef23073` | PASS | 200 | 3.59 |  |
| `vpn_stop` | PASS | 200 | 8.61 |  |
| `governance_approve_ec79af5adb25ebe2` | PASS | 200 | 4.68 |  |
| `deception_assess_risk` | PASS | 200 | 1.70 |  |
| `deception_decoy_interaction` | PASS | 200 | 7.29 |  |
| `threat_intel_check_indicator` | PASS | 200 | 1.22 |  |
| `honey_token_create_api_key` | PASS | 200 | 1.99 |  |
| `honey_token_toggle` | PASS | 200 | 1.35 |  |
| `honeypot_create` | PASS | 200 | 1.41 |  |
| `honeypot_record_interaction` | PASS | 200 | 1.85 |  |
| `soar_trigger_playbook` | PASS | 200 | 10.51 |  |
| `enterprise_policy_evaluate` | PASS | 200 | 3.78 |  |
| `cspm_scan_trigger` | PASS | 200 | 2.44 |  |
| `container_image_scan` | PASS | 200 | 7.80 |  |
| `quantum_generate_dilithium_keypair` | PASS | 200 | 3.62 |  |
| `quantum_sign` | PASS | 200 | 2.32 |  |
| `quantum_verify_stored_signature` | PASS | 200 | 2.92 |  |
| `quantum_hash_data` | PASS | 200 | 2.25 |  |
| `quantum_generate_kyber_keypair` | PASS | 200 | 3.17 |  |
| `quantum_encrypt_payload` | PASS | 200 | 2.53 |  |
| `ai_defense_escalate` | PASS | 200 | 1.57 |  |
| `ai_defense_deploy_decoy` | PASS | 200 | 1.50 |  |
| `ai_defense_engage_tarpit` | PASS | 200 | 1.63 |  |
| `agent_event_ingest` | PASS | 200 | 1.13 |  |
| `cli_event_ingest` | PASS | 200 | 1.70 |  |
| `extension_report_alerts` | PASS | 200 | 1.47 |  |
| `enterprise_machine_token_boundary` | PASS | 401 | 1.37 |  |
| `swarm_cli_machine_token_boundary` | PASS | 401 | 1.11 |  |
| `containers_falco_status` | PASS | 200 | 1.58 |  |
| `containers_falco_alerts` | PASS | 200 | 1.25 |  |
| `containers_suricata_stats` | PASS | 200 | 0.99 |  |
| `containers_suricata_alerts` | PASS | 200 | 1.28 |  |
| `zeek_status` | PASS | 200 | 1.70 |  |
| `zeek_stats` | PASS | 200 | 1.83 |  |
| `zeek_detection_beaconing` | PASS | 200 | 1.81 |  |
| `zeek_detection_dns_tunneling` | PASS | 200 | 1.88 |  |
| `elasticsearch_status` | PASS | 200 | 1.24 |  |
| `kibana_status` | PASS | 200 | 1.72 |  |
| `kibana_dashboards` | PASS | 200 | 1.47 |  |
| `advanced_sandbox_status` | PASS | 200 | 2.09 |  |
| `containers_yara_status` | PASS | 200 | 2.09 |  |
| `correlation_all_active` | PASS | 200 | 3.11 |  |
| `timeline_recent` | PASS | 200 | 1.75 |  |
| `audit_recent` | PASS | 200 | 1.29 |  |
| `mitre_coverage_snapshot` | PASS | 200 | 62.18 |  |
| `assert_ingest_artifacts_created` | PASS | 200 | 0.00 | artifacts=1fbf2d94-2601-4363-b7e9-65f12c82c626,email_dd5ae00bbd2c,mobile_d0f1237dd2da |
| `assert_governance_queue_created` | PASS | 200 | 0.00 | proposal_status=queued_for_triune_approval |
| `assert_decision_visible_or_pending_increased` | PASS | 200 | 0.00 | pending_before=1 pending_after=2 decision_visible=True |
| `assert_approved_decision_executed` | PASS | 200 | 0.00 | approve_summary={'processed': 1, 'executed': 1, 'skipped': 0, 'failed': 0} |
| `assert_mitre_feedback_available` | PASS | 200 | 0.00 | mitre_snapshot={'coverage_percent_gte3': 81.48, 'covered_score_gte3': 259, 'covered_score_gte4': 216, 'observed_techniques': 299} |
