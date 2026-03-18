# Threat Pipeline E2E Report

- Generated: 2026-03-16T22:03:56.141733+00:00
- Base URL: `http://127.0.0.1:8001/api`
- Total Steps: **79**
- Passed: **76**
- Failed: **3**
- Pass Rate: **96.2%**
- Avg Latency: **540.64 ms**

## Domain Summary

| Domain | Passed | Total | Pass Rate |
|---|---:|---:|---:|
| `ai_ml` | 4 | 4 | 100.0% |
| `analytics_reporting` | 2 | 2 | 100.0% |
| `celery` | 0 | 1 | 0.0% |
| `cloud_cspm` | 1 | 1 | 100.0% |
| `container_security` | 3 | 3 | 100.0% |
| `core_auth` | 2 | 2 | 100.0% |
| `deception` | 6 | 6 | 100.0% |
| `email_web` | 3 | 3 | 100.0% |
| `endpoint_unified_agent` | 5 | 5 | 100.0% |
| `enterprise_policy` | 2 | 2 | 100.0% |
| `governance` | 9 | 9 | 100.0% |
| `hunting_correlation` | 1 | 1 | 100.0% |
| `integrations` | 0 | 2 | 0.0% |
| `mitre_posture` | 1 | 1 | 100.0% |
| `mobile_mdm` | 2 | 2 | 100.0% |
| `network_response` | 1 | 1 | 100.0% |
| `quantum_security` | 6 | 6 | 100.0% |
| `sandbox` | 1 | 1 | 100.0% |
| `soar` | 1 | 1 | 100.0% |
| `stack_observability` | 13 | 13 | 100.0% |
| `threat_intel` | 1 | 1 | 100.0% |
| `threat_management` | 1 | 1 | 100.0% |
| `vpn` | 3 | 3 | 100.0% |
| `zero_trust` | 3 | 3 | 100.0% |

## Pipeline Artifacts

```json
{
  "user_email": "threat-e2e-86ba6858@local",
  "threat_id": "c4c682ad-d24f-4be5-b28d-df4af3e8ccb7",
  "aatl_response": {
    "session_id": "sess-4f46da1d",
    "host_id": "finance-workstation-07",
    "timestamp": "2026-03-16T22:03:18.067841+00:00",
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
  "email_assessment_id": "email_12c6abcdd3ca",
  "email_threat_score": 0.3,
  "browser_session_id": "iso_11990199045f",
  "mobile_device_id": "mobile_709c1a052327",
  "pending_before": 75,
  "agent_id": "e2e-agent-e17c14cf",
  "agent_auth_token_present": true,
  "decision_id": "8542f39fa66c521e",
  "proposal_status": "queued_for_triune_approval",
  "pending_after": 76,
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
  "container_scan_report_available": true,
  "advanced_stack_snapshot": {
    "falco_available": false,
    "falco_alert_count": 0,
    "suricata_available": true,
    "zeek_available": false,
    "elasticsearch_connected": false,
    "kibana_configured": true,
    "sandbox_available": false,
    "yara_available": true
  },
  "correlation_summary": {
    "total": 5,
    "high_confidence": 0,
    "medium_confidence": 0,
    "low_confidence": 5,
    "no_correlation": 0
  },
  "timeline_count": 8,
  "audit_recent_count": 0,
  "mitre_snapshot": {
    "coverage_percent_gte3": 91.67,
    "covered_score_gte3": 284,
    "covered_score_gte4": 241,
    "observed_techniques": 322
  }
}
```

## Step Results

| Step | Result | HTTP | Latency (ms) | Details |
|---|---|---:|---:|---|
| `register_user` | PASS | 200 | 1136.37 |  |
| `login_user` | PASS | 200 | 471.69 |  |
| `create_threat` | PASS | 200 | 226.44 |  |
| `aatl_analyze_cli_session` | PASS | 200 | 124.40 |  |
| `email_protection_analyze` | PASS | 200 | 2029.37 |  |
| `browser_isolation_session_create` | PASS | 200 | 1071.65 |  |
| `mobile_register_device` | PASS | 200 | 68.18 |  |
| `mobile_update_device_status` | PASS | 200 | 58.51 |  |
| `governance_pending_before` | PASS | 200 | 158.40 |  |
| `unified_agent_register` | PASS | 200 | 77.41 |  |
| `unified_agent_heartbeat` | PASS | 200 | 1030.37 |  |
| `remediation_propose_block_ip` | PASS | 200 | 2158.63 |  |
| `governance_pending_after` | PASS | 200 | 109.81 |  |
| `governance_approve_decision` | PASS | 200 | 181.98 |  |
| `governance_executor_run_once` | PASS | 200 | 69.83 |  |
| `threat_response_block_ip` | PASS | 200 | 760.85 |  |
| `governance_approve_2225843b564f60c3` | PASS | 200 | 565.98 |  |
| `zero_trust_register_device` | PASS | 200 | 94.76 |  |
| `zero_trust_evaluate_access` | PASS | 200 | 81.60 |  |
| `zero_trust_trust_score` | PASS | 200 | 46.80 |  |
| `vpn_add_peer` | PASS | 200 | 612.24 |  |
| `governance_approve_22f4c291e2be57f6` | PASS | 200 | 186.35 |  |
| `vpn_start` | PASS | 200 | 388.01 |  |
| `governance_approve_c9f4953b278de3c4` | PASS | 200 | 586.68 |  |
| `vpn_stop` | PASS | 200 | 271.18 |  |
| `governance_approve_67bdbebc14a9dc87` | PASS | 200 | 514.48 |  |
| `deception_assess_risk` | PASS | 200 | 28.06 |  |
| `deception_decoy_interaction` | PASS | 200 | 210.99 |  |
| `threat_intel_check_indicator` | PASS | 200 | 19.95 |  |
| `honey_token_create_api_key` | PASS | 200 | 27.92 |  |
| `honey_token_toggle` | PASS | 200 | 12.62 |  |
| `honeypot_create` | PASS | 200 | 23.89 |  |
| `honeypot_record_interaction` | PASS | 200 | 19.54 |  |
| `soar_trigger_playbook` | PASS | 200 | 470.70 |  |
| `enterprise_policy_evaluate` | PASS | 200 | 36.47 |  |
| `cspm_scan_trigger` | PASS | 200 | 38.09 |  |
| `container_image_scan` | PASS | 200 | 119.33 |  |
| `quantum_generate_dilithium_keypair` | PASS | 200 | 27.67 |  |
| `quantum_sign` | PASS | 200 | 25.49 |  |
| `quantum_verify_stored_signature` | PASS | 200 | 27.28 |  |
| `quantum_hash_data` | PASS | 200 | 21.04 |  |
| `quantum_generate_kyber_keypair` | PASS | 200 | 40.80 |  |
| `quantum_encrypt_payload` | PASS | 200 | 22.75 |  |
| `ai_defense_escalate` | PASS | 200 | 18.52 |  |
| `ai_defense_deploy_decoy` | PASS | 200 | 13.11 |  |
| `ai_defense_engage_tarpit` | PASS | 200 | 13.16 |  |
| `agent_event_ingest` | PASS | 200 | 12.96 |  |
| `cli_event_ingest` | PASS | 200 | 25.82 |  |
| `extension_report_alerts` | PASS | 200 | 11.97 |  |
| `enterprise_machine_token_boundary` | PASS | 401 | 9.06 |  |
| `swarm_cli_machine_token_boundary` | PASS | 401 | 9.80 |  |
| `sandbox_submit` | PASS | 200 | 317.42 |  |
| `container_image_scan_deep` | PASS | 200 | 5051.69 |  |
| `poll_containers_scans_history` | PASS | 200 | 391.87 |  |
| `ollama_ping` | FAIL | 404 | 11.92 | {"detail":"Not Found"} |
| `integrations_list` | FAIL | 404 | 6.56 | {"detail":"Not Found"} |
| `celery_trigger_sample_task` | FAIL | 404 | 9.76 | {"detail":"Not Found"} |
| `containers_falco_status` | PASS | 200 | 9.90 |  |
| `containers_falco_alerts` | PASS | 200 | 9.91 |  |
| `containers_suricata_stats` | PASS | 200 | 8296.68 |  |
| `containers_suricata_alerts` | PASS | 200 | 9600.28 |  |
| `zeek_status` | PASS | 200 | 41.12 |  |
| `zeek_stats` | PASS | 200 | 11.52 |  |
| `zeek_detection_beaconing` | PASS | 200 | 11.58 |  |
| `zeek_detection_dns_tunneling` | PASS | 200 | 8.17 |  |
| `elasticsearch_status` | PASS | 200 | 9.89 |  |
| `kibana_status` | PASS | 200 | 9.96 |  |
| `kibana_dashboards` | PASS | 200 | 9.70 |  |
| `advanced_sandbox_status` | PASS | 200 | 8.99 |  |
| `containers_yara_status` | PASS | 200 | 21.08 |  |
| `correlation_all_active` | PASS | 200 | 60.27 |  |
| `timeline_recent` | PASS | 200 | 24.50 |  |
| `audit_recent` | PASS | 200 | 12.55 |  |
| `mitre_coverage_snapshot` | PASS | 200 | 1703.37 |  |
| `assert_ingest_artifacts_created` | PASS | 200 | 0.00 | artifacts=c4c682ad-d24f-4be5-b28d-df4af3e8ccb7,email_12c6abcdd3ca,mobile_709c1a052327 |
| `assert_governance_queue_created` | PASS | 200 | 0.00 | proposal_status=queued_for_triune_approval |
| `assert_decision_visible_or_pending_increased` | PASS | 200 | 0.00 | pending_before=75 pending_after=76 decision_visible=True |
| `assert_approved_decision_executed` | PASS | 200 | 0.00 | approve_summary={'processed': 1, 'executed': 1, 'skipped': 0, 'failed': 0} |
| `assert_mitre_feedback_available` | PASS | 200 | 0.00 | mitre_snapshot={'coverage_percent_gte3': 91.67, 'covered_score_gte3': 284, 'covered_score_gte4': 241, 'observed_techniques': 322} |
