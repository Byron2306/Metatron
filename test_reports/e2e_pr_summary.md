# E2E Threat Pipeline — PR Summary

Generated: 2026-03-16T21:20:09Z

Base URL used: http://127.0.0.1:8001/api

Total steps: 123
Passed: 74
Failed: 49
Pass rate: 60.16%
Composite score: 74.05/100 (rating: strong)

Failing integrations and notes:
- Sandbox / Cuckoo: containers running but sandbox polling returned no report (sandbox_report_available=false). Check backend->sandbox job ingestion and Cuckoo processing.
- Container scanning (Trivy): deep scan polling returned incomplete results (container_scan_report_available=false).
- Integrations (Ollama, generic): ping/list endpoints failed in this run.
- Polling steps: many `poll_*` steps timed out; consider increasing polling timeouts or verifying Celery workers.

Reports:
- test_reports/threat_pipeline_e2e_report.json
- test_reports/system_scoring_report.json
- test_reports/threat_pipeline_e2e_report.md

Next actions (suggested):
1. Inspect backend/Celery logs for tasks related to sandbox and container scans.
2. Manually submit a sandbox job and poll Cuckoo web API for a report.
3. Increase `E2E_REQUEST_TIMEOUT` or polling timeouts and re-run the E2E.
4. If you want, I can perform (2) now and report back.
