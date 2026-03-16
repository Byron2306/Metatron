# Threat Pipeline E2E Report

- Generated: 2026-03-16T02:06:27.070763+00:00
- Base URL: `http://127.0.0.1:8001/api`
- Total Steps: **24**
- Passed: **24**
- Failed: **0**
- Pass Rate: **100.0%**
- Avg Latency: **29.43 ms**

## Pipeline Artifacts

```json
{
  "user_email": "threat-e2e-d3967a35@local",
  "threat_id": "01864caa-4854-4095-a5ef-41aecc6e3a12",
  "aatl_response": {
    "session_id": "sess-a2b134d8",
    "host_id": "finance-workstation-07",
    "timestamp": "2026-03-16T02:06:26.950990+00:00",
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
  "email_assessment_id": "email_4974b1721b6a",
  "email_threat_score": 0.3,
  "browser_session_id": "iso_27307998550d",
  "mobile_device_id": "mobile_b17da100553e",
  "pending_before": 3,
  "agent_id": "e2e-agent-6377a372",
  "agent_auth_token_present": true,
  "decision_id": "6fd508e24535020f",
  "proposal_status": "queued_for_triune_approval",
  "pending_after": 4,
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
    "total": 2,
    "high_confidence": 0,
    "medium_confidence": 0,
    "low_confidence": 1,
    "no_correlation": 1
  },
  "timeline_count": 2,
  "audit_recent_count": 0,
  "mitre_snapshot": {
    "coverage_percent_gte3": 71.3,
    "covered_score_gte3": 214,
    "covered_score_gte4": 115,
    "observed_techniques": 280
  }
}
```

## Step Results

| Step | Result | HTTP | Latency (ms) | Details |
|---|---|---:|---:|---|
| `register_user` | PASS | 200 | 216.68 |  |
| `login_user` | PASS | 200 | 215.43 |  |
| `create_threat` | PASS | 200 | 2.45 |  |
| `aatl_analyze_cli_session` | PASS | 200 | 6.67 |  |
| `email_protection_analyze` | PASS | 200 | 28.01 |  |
| `browser_isolation_session_create` | PASS | 200 | 22.32 |  |
| `mobile_register_device` | PASS | 200 | 2.51 |  |
| `mobile_update_device_status` | PASS | 200 | 2.97 |  |
| `governance_pending_before` | PASS | 200 | 2.47 |  |
| `unified_agent_register` | PASS | 200 | 2.12 |  |
| `unified_agent_heartbeat` | PASS | 200 | 4.51 |  |
| `remediation_propose_block_ip` | PASS | 200 | 8.37 |  |
| `governance_pending_after` | PASS | 200 | 2.52 |  |
| `governance_approve_decision` | PASS | 200 | 4.31 |  |
| `governance_executor_run_once` | PASS | 200 | 2.26 |  |
| `correlation_all_active` | PASS | 200 | 3.18 |  |
| `timeline_recent` | PASS | 200 | 1.54 |  |
| `audit_recent` | PASS | 200 | 1.18 |  |
| `mitre_coverage_snapshot` | PASS | 200 | 29.59 |  |
| `assert_ingest_artifacts_created` | PASS | 200 | 0.00 | artifacts=01864caa-4854-4095-a5ef-41aecc6e3a12,email_4974b1721b6a,mobile_b17da100553e |
| `assert_governance_queue_created` | PASS | 200 | 0.00 | proposal_status=queued_for_triune_approval |
| `assert_decision_visible_or_pending_increased` | PASS | 200 | 0.00 | pending_before=3 pending_after=4 decision_visible=True |
| `assert_approved_decision_executed` | PASS | 200 | 0.00 | approve_summary={'processed': 1, 'executed': 1, 'skipped': 0, 'failed': 0} |
| `assert_mitre_feedback_available` | PASS | 200 | 0.00 | mitre_snapshot={'coverage_percent_gte3': 71.3, 'covered_score_gte3': 214, 'covered_score_gte4': 115, 'observed_techniques': 280} |
