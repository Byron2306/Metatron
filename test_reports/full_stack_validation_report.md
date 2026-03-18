# Full Stack Validation Report

- Generated: 2026-03-16T06:53:28.722336+00:00
- Overall Passed: **False**
- Base URL: `http://127.0.0.1:8011/api`

## Compose Services

- Declared services: **0**
- Running services: **0**
- Missing required services: **18**

```json
{
  "docker_available": false,
  "steps": [
    {
      "cmd": "docker compose ...",
      "returncode": 127,
      "stdout": "",
      "stderr": "docker executable not found on PATH",
      "elapsed_ms": 0.0
    }
  ],
  "declared_services": [],
  "running_services": [],
  "required_services": [
    "mongodb",
    "redis",
    "backend",
    "frontend",
    "celery-worker",
    "celery-beat",
    "elasticsearch",
    "kibana",
    "trivy",
    "falco",
    "suricata",
    "zeek",
    "volatility",
    "wireguard",
    "nginx",
    "cuckoo-mongo",
    "cuckoo",
    "cuckoo-web"
  ],
  "missing_required_services": [
    "backend",
    "celery-beat",
    "celery-worker",
    "cuckoo",
    "cuckoo-mongo",
    "cuckoo-web",
    "elasticsearch",
    "falco",
    "frontend",
    "kibana",
    "mongodb",
    "nginx",
    "redis",
    "suricata",
    "trivy",
    "volatility",
    "wireguard",
    "zeek"
  ]
}
```

## Readiness Checks

```json
{
  "backend_health": {
    "ok": true,
    "status_code": 200,
    "attempts": 1,
    "elapsed_ms": 4.5
  },
  "frontend_root": {
    "ok": null,
    "skipped": true,
    "reason": "docker unavailable in current runtime"
  },
  "kibana_root": {
    "ok": null,
    "skipped": true,
    "reason": "docker unavailable in current runtime"
  },
  "elasticsearch_root": {
    "ok": null,
    "skipped": true,
    "reason": "docker unavailable in current runtime"
  }
}
```

## API Probes

| Method | Path | Status | OK |
|---|---|---:|---|
| `GET` | `/containers/falco/status` | 200 | True |
| `GET` | `/containers/suricata/stats` | 200 | True |
| `GET` | `/zeek/status` | 200 | True |
| `GET` | `/advanced/sandbox/status` | 200 | True |
| `GET` | `/settings/elasticsearch/status` | 200 | True |
| `GET` | `/kibana/status` | 200 | True |
| `GET` | `/mitre/coverage?profile=balanced` | 200 | True |
| `GET` | `/mitre/coverage?profile=hardened` | 200 | True |

## Suite Runs

| Command | Exit | OK | Duration (ms) |
|---|---:|---|---:|
| `/usr/bin/python3 backend/scripts/e2e_endpoint_sweep.py` | 0 | True | 106.9 |
| `/usr/bin/python3 backend/scripts/e2e_threat_pipeline_test.py` | 0 | True | 822.05 |
| `/usr/bin/python3 backend/scripts/mitre_coverage_evidence_report.py` | 0 | True | 490.54 |
