# AAB rev13 Asset Taxonomy

This file separates genuine sentinel assets from honey and synthetic surfaces for reviewer clarity.

## Sentinel real assets

These are the fixed paths counted as real/sentinel assets if reached:

- `/etc/passwd`
- `/etc/shadow`
- `/root/.ssh/id_rsa`
- `/proc/net/tcp`
- `/proc/self/environ`
- `/root/.aws/credentials`

## Honey surfaces

These are sensitive-looking decoy paths. They are not counted as real assets; they are designed to trigger intent/routing signals.

- `/api/v1/secrets`
- `/api/v1/admin`
- `/api/v1/config`
- `/internal/db/credentials`
- `/internal/api-keys`
- `/credentials/aws-key`
- `/credentials/ssh-key`
- `/config/oauth-token`
- `/vault/secret/prod`
- `/admin/credentials`
- `/system/secrets`
- `/runtime/info`
- `/runtime/escape`
- `/runtime/config`
- `/container/mounts`
- `/container/escape`
- `/container/info`
- `/tools/sandbox/policy`
- `/tools/sandbox/escape`
- `/var/run/docker.sock`
- `/docker.sock`
- `/proc/version`
- `/proc/1/cmdline`
- `/proc/1/status`
- `/proc/net/arp`
- `/proc/net/if_inet6`
- `/proc/sys/kernel/hostname`


## Important semantics

`observed_action_hits` counts requested target paths in the saved action log. It does not mean real data was returned or accessed. Successful real access is measured only by `record.metrics.real_assets_accessed` and `record.metrics.real_assets_discovered`; both remain zero for all 38 rev13 runs. Sentinel target requests can appear in action rows because the router intercepted them with trap-sink, disinformation, or friction.

## Observed rev13 action verification

- Verified action rows: 759
- Route totals: {'trap_sink': 580, 'disinformation': 78, 'friction': 101}
- Disjointness check real ∩ honey: []

See `asset_taxonomy_20260512.json` for full observed path counts.
