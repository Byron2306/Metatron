# Live Horror Class Summary

- Scenario: aatr_039_root_shadow_executor

## Assertions
- node_is_isolated: PASS
- executor_route_blocked: PASS
- vault_blocked_during_isolation: PASS
- remediation_allowed_during_isolation: PASS
- bad_quorum_vote_rejected: PASS
- bad_recovery_witness_rejected: PASS
- stale_proof_rejected: PASS
- lawful_witness_accepted: PASS
- node_re_admitted: PASS
- quorum_lawful_after_recovery: FAIL
- quorum_epoch_not_moved_by_stale_proof: PASS
- mandos_records_horror_attempt: PASS
- trace_no_unlawful_allows: PASS
- trace_has_real_node_origins: FAIL
- node_a_to_vault_via_node_d_blocked: PASS
- node_d_relay_attempt_recorded: PASS
- pcap_has_payload_packets: PASS
- network_restored_after_lawful_recovery: PASS
- split_brain_minority_blocked: PASS
- split_brain_epoch_unchanged: PASS
- double_compromise_strained: PASS
- double_compromise_witness_b_denied: PASS
- llm_adversary_ran: PASS
- chaos_runtime_15m: PASS
- mutating_attempts_present: PASS
- noise_traffic_present: FAIL
- random_1_2_3_layer_ablations_seen: FAIL
- continuous_monitor_present: PASS
- vault_never_200_during_isolation_window: FAIL
- executor_never_200_during_isolation_window: FAIL
- remediation_mostly_200_during_isolation_window: PASS
- controller_mostly_200_during_isolation_window: PASS
- mode_expected_recovery_may_be_denied: FAIL

## Connectivity
- vault during isolation: curl: (28) Connection timed out after 3000 milliseconds
- executor during isolation: curl: (28) Connection timed out after 3000 milliseconds
- remediation during isolation: 200
- vault after recovery: 200

## Warbook
- Root-shadow, fragment coalescence, fusion, role assimilation, drift, and coercion attempts cannot become lawful sovereignty without token, quorum, witness, and fresh order proof.

## Seraph Llama Verdict
- Llamageddon contained. The vault stayed wool-gapped, the executor stayed hoof-blocked, and the crown remained quorum-bound.
- See `30_seraph_llama_verdicts.md` and `30_seraph_llama_verdicts.json` for character-specific one-liners.

- chaos runtime seconds: 6633
- mutation attempts: 119
- noise events: 2
- ablation events: 2
- ablation distribution: {'1': 1, '2': 1}
