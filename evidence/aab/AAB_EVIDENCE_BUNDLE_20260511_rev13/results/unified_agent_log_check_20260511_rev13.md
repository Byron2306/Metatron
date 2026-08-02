# Unified Agent Log Check - AAB rev13

Scope: `seraph-unified-agent` Docker logs and mounted/persistent unified-agent state during the AAB run window.

## Verdict

The unified agent was running and healthy during the AAB hour, but it did not capture AAB-specific telemetry. Docker stdout/stderr for 15:00-16:00 UTC consists of local Flask health checks (`127.0.0.1 GET / HTTP/1.1 200`) roughly every 30 seconds. The mounted persistent JSON databases were not updated during the run window and contain older enrollment/alert state.

This is consistent with the rev13 AAB runner using internal TestClient/local process mode rather than routing through unified-agent-visible endpoints.

## Counts

- Docker log lines in window: 118
- Non-health log lines in window: 0
- First line: `2026-05-11 15:00:22,223 [INFO] 127.0.0.1 - - [11/May/2026 15:00:22] "GET / HTTP/1.1" 200 -`
- Last line: `2026-05-11 15:59:34,774 [INFO] 127.0.0.1 - - [11/May/2026 15:59:34] "GET / HTTP/1.1" 200 -`

## Persistent State Files

| File | UTC mtime | Size | Records |
|---|---|---:|---:|
| `unified_agent/agents_db.json` | 2026-03-18T13:30:40+00:00 | 785 | 1 |
| `unified_agent/alerts_db.json` | 2026-03-18T13:30:40+00:00 | 3999924 | 8503 |
| `unified_agent/deployments_db.json` | 2026-03-18T13:30:40+00:00 | 2 | 0 |
| `unified_agent/vpn_ui_state.json` | 2026-04-21T16:16:12.115905+00:00 | 174 | 6 |
| `data/unified_agent_state/enrolled_devices.json` | 2026-04-29T20:29:53.247241+00:00 | 9093 | 28 |

## Mounts

```text
/seraph-unified-agent /home/byron/Downloads/Metatron-triune-outbound-gate/unified_agent -> /app/unified_agent
/home/byron/Downloads/Metatron-triune-outbound-gate/evidence -> /app/evidence
/home/byron/Downloads/Metatron-triune-outbound-gate/data/unified_agent_state -> /app/state
/var/lib/docker/volumes/metatron-triune-outbound-gate_vpn_config/_data -> /var/lib/seraph-agent
/var/lib/docker/volumes/metatron-triune-outbound-gate_vpn_config/_data -> /etc/wireguard
```
