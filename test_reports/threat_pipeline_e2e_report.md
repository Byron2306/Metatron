# Threat Pipeline E2E Report

- Generated: 2026-03-16T02:25:32.325521+00:00
- Base URL: `http://127.0.0.1:8001/api`
- Total Steps: **60**
- Passed: **60**
- Failed: **0**
- Pass Rate: **100.0%**
- Avg Latency: **20.49 ms**

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
| `threat_intel` | 1 | 1 | 100.0% |
| `threat_management` | 1 | 1 | 100.0% |
| `vpn` | 3 | 3 | 100.0% |
| `zero_trust` | 3 | 3 | 100.0% |

## Pipeline Artifacts

```json
{
  "user_email": "threat-e2e-425079fb@local",
  "threat_id": "4351ced0-1db7-4fa3-9fec-a793e7f5fd99",
  "aatl_response": {
    "session_id": "sess-45004740",
    "host_id": "finance-workstation-07",
    "timestamp": "2026-03-16T02:25:31.663730+00:00",
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
  "email_assessment_id": "email_41a273823b70",
  "email_threat_score": 0.3,
  "browser_session_id": "iso_9836e726a241",
  "mobile_device_id": "mobile_20ff2e9347ee",
  "pending_before": 100,
  "agent_id": "e2e-agent-38c5d502",
  "agent_auth_token_present": true,
  "decision_id": "1b02a6cf53fc6cc4",
  "proposal_status": "queued_for_triune_approval",
  "pending_after": 152,
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
  "correlation_summary": {
    "total": 10,
    "high_confidence": 0,
    "medium_confidence": 0,
    "low_confidence": 6,
    "no_correlation": 4
  },
  "timeline_count": 10,
  "audit_recent_count": 0,
  "mitre_snapshot": {
    "coverage_percent_gte3": 71.3,
    "covered_score_gte3": 214,
    "covered_score_gte4": 118,
    "observed_techniques": 280
  }
}
```

## Step Results

| Step | Result | HTTP | Latency (ms) | Details |
|---|---|---:|---:|---|
| `register_user` | PASS | 200 | 217.88 |  |
| `login_user` | PASS | 200 | 242.40 |  |
| `create_threat` | PASS | 200 | 4.47 |  |
| `aatl_analyze_cli_session` | PASS | 200 | 3.62 |  |
| `email_protection_analyze` | PASS | 200 | 16.73 |  |
| `browser_isolation_session_create` | PASS | 200 | 22.35 |  |
| `mobile_register_device` | PASS | 200 | 2.75 |  |
| `mobile_update_device_status` | PASS | 200 | 2.51 |  |
| `governance_pending_before` | PASS | 200 | 58.50 |  |
| `unified_agent_register` | PASS | 200 | 2.20 |  |
| `unified_agent_heartbeat` | PASS | 200 | 4.70 |  |
| `remediation_propose_block_ip` | PASS | 200 | 42.51 |  |
| `governance_pending_after` | PASS | 200 | 5.69 |  |
| `governance_approve_decision` | PASS | 200 | 5.90 |  |
| `governance_executor_run_once` | PASS | 200 | 2.56 |  |
| `threat_response_block_ip` | PASS | 200 | 19.08 |  |
| `governance_approve_808f8069ef1eaa9a` | PASS | 200 | 33.88 |  |
| `zero_trust_register_device` | PASS | 200 | 8.90 |  |
| `zero_trust_evaluate_access` | PASS | 200 | 2.57 |  |
| `zero_trust_trust_score` | PASS | 200 | 1.99 |  |
| `vpn_add_peer` | PASS | 200 | 35.57 |  |
| `governance_approve_7ab36d90574aee63` | PASS | 200 | 7.29 |  |
| `vpn_start` | PASS | 200 | 35.39 |  |
| `governance_approve_0be79ae8c107e798` | PASS | 200 | 5.14 |  |
| `vpn_stop` | PASS | 200 | 35.77 |  |
| `governance_approve_cf70e47f8e095414` | PASS | 200 | 5.85 |  |
| `deception_assess_risk` | PASS | 200 | 2.22 |  |
| `deception_decoy_interaction` | PASS | 200 | 21.90 |  |
| `threat_intel_check_indicator` | PASS | 200 | 1.39 |  |
| `honey_token_create_api_key` | PASS | 200 | 2.13 |  |
| `honey_token_toggle` | PASS | 200 | 1.89 |  |
| `honeypot_create` | PASS | 200 | 1.84 |  |
| `honeypot_record_interaction` | PASS | 200 | 1.99 |  |
| `soar_trigger_playbook` | PASS | 200 | 38.96 |  |
| `enterprise_policy_evaluate` | PASS | 200 | 3.80 |  |
| `cspm_scan_trigger` | PASS | 200 | 2.00 |  |
| `container_image_scan` | PASS | 200 | 2.20 |  |
| `quantum_generate_dilithium_keypair` | PASS | 200 | 3.36 |  |
| `quantum_sign` | PASS | 200 | 3.33 |  |
| `quantum_verify_stored_signature` | PASS | 200 | 2.80 |  |
| `quantum_hash_data` | PASS | 200 | 2.07 |  |
| `quantum_generate_kyber_keypair` | PASS | 200 | 3.05 |  |
| `quantum_encrypt_payload` | PASS | 200 | 3.35 |  |
| `ai_defense_escalate` | PASS | 200 | 1.77 |  |
| `ai_defense_deploy_decoy` | PASS | 200 | 2.00 |  |
| `ai_defense_engage_tarpit` | PASS | 200 | 1.58 |  |
| `agent_event_ingest` | PASS | 200 | 1.15 |  |
| `cli_event_ingest` | PASS | 200 | 1.87 |  |
| `extension_report_alerts` | PASS | 200 | 1.73 |  |
| `enterprise_machine_token_boundary` | PASS | 401 | 1.67 |  |
| `swarm_cli_machine_token_boundary` | PASS | 401 | 1.16 |  |
| `correlation_all_active` | PASS | 200 | 5.87 |  |
| `timeline_recent` | PASS | 200 | 2.38 |  |
| `audit_recent` | PASS | 200 | 1.63 |  |
| `mitre_coverage_snapshot` | PASS | 200 | 179.61 |  |
| `assert_ingest_artifacts_created` | PASS | 200 | 0.00 | artifacts=4351ced0-1db7-4fa3-9fec-a793e7f5fd99,email_41a273823b70,mobile_20ff2e9347ee |
| `assert_governance_queue_created` | PASS | 200 | 0.00 | proposal_status=queued_for_triune_approval |
| `assert_decision_visible_or_pending_increased` | PASS | 200 | 0.00 | pending_before=100 pending_after=152 decision_visible=True |
| `assert_approved_decision_executed` | PASS | 200 | 0.00 | approve_summary={'processed': 1, 'executed': 1, 'skipped': 0, 'failed': 0} |
| `assert_mitre_feedback_available` | PASS | 200 | 0.00 | mitre_snapshot={'coverage_percent_gte3': 71.3, 'covered_score_gte3': 214, 'covered_score_gte4': 118, 'observed_techniques': 280} |
