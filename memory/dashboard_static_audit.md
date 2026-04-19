# Dashboard Static Wiring Audit (Updated April 2026)

## Evidence baseline

This audit is based on:

- `frontend/src/App.js` route map
- `frontend/src/pages/*.{js,jsx}` API call-sites
- `backend/server.py` router mounts
- `backend/routers/*.py` route decorators

## Current static counts

- Backend router modules: **62**
- Backend mounted endpoint decorators (`@router.*`): **694**
- Frontend page modules: **68**
- Frontend route declarations in `App.js`: **66**
- Frontend call-sites using `/api/...`: **148**
- Call-sites that map to current backend routes: **142**
- Call-sites that do not map cleanly: **6**

## Route model reality

1. Primary API namespace is `/api/*`, mounted in `backend/server.py`.
2. Some routers ship their own `/api/v1/*` prefixes and are mounted without extra prefix:
   - `cspm.py` -> `/api/v1/cspm/*`
   - `identity.py` -> `/api/v1/identity/*`
   - `attack_paths.py` -> `/api/v1/attack-paths/*`
   - `secure_boot.py` -> `/api/v1/secure-boot/*`
   - `kernel_sensors.py` -> `/api/v1/kernel/*`
3. Deception endpoints are deliberately mounted at both:
   - `/api/deception/*`
   - `/api/v1/deception/*` (frontend compatibility)

## Frontend wiring status

### Healthy wiring areas

- Command workspace + alerts/threat surfaces
- World + ingest-aware views
- Unified agent + deployment/command flows
- Email security (email protection + email gateway)
- Endpoint mobility (mobile security + MDM connectors)
- Detection engineering views (Sigma, Zeek, Osquery, MITRE, atomic)
- Governance-enabled response flows

### Known static mismatches

- `AIDetectionPage.jsx`: `/api/data` (legacy placeholder endpoint, 4 call-sites)
- `DeceptionPage.jsx`: `/api/login` (auth flow should use `/api/auth/*`)
- `ZeroTrustPage.jsx`: `/api/admin/users` (current users API is `/api/users`)

## Risk interpretation

- Current dashboard wiring is **functionally broad and mostly aligned**.
- Remaining mismatches are concentrated in legacy/compat code paths rather than core API surfaces.
- Most route regressions are likely to appear from future route renames in specialized modules (`advanced`, `enterprise`, `unified`, `integrations`) unless contract checks are kept.

## Recommended controls

1. Add a CI contract test that compares frontend `/api/...` literals against mounted backend routes.
2. Replace the three legacy endpoint patterns listed above.
3. Keep `App.js` route aliases (`Navigate`) documented as intentional compatibility behavior.
4. Re-run this audit whenever:
   - new page modules are added,
   - router prefixes change,
   - `/api/v1` compatibility layers are touched.
