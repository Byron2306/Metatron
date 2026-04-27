# Dashboard Static Wiring Audit

Updated: 2026-04-27

- Current UI routing in `frontend/src/App.js` is workspace-oriented. Several older direct routes intentionally redirect into workspace tabs rather than rendering separate pages.
- Treat redirects such as `/alerts` -> `/command?tab=alerts`, `/threats` -> `/command?tab=threats`, `/email-gateway` -> `/email-security?tab=gateway`, and `/mdm` -> `/endpoint-mobility?tab=mdm` as valid wiring when reviewing current code.
- Static call-site counts below are retained as the previous audit baseline; rerun the audit before using them as exact current totals.

- Backend routes total: 397
- Frontend call-sites checked: 66
- Matched call-sites: 65
- Unmatched call-sites: 1
- Buttons without clear action attrs: 7

## Unmatched call-sites
- frontend/src/pages/MLPredictionPage.jsx:66 -> /api/ml/predict/X (dynamic-type-path)
  - expr: ${API_URL}/api/ml/predict/${type}

## Buttons without clear action attrs
- frontend/src/pages/HoneypotsPage.jsx:276
- frontend/src/pages/AgentsPage.jsx:230
- frontend/src/pages/UnifiedAgentPage.jsx:369
- frontend/src/pages/UnifiedAgentPage.jsx:373
- frontend/src/pages/UnifiedAgentPage.jsx:377
- frontend/src/pages/UnifiedAgentPage.jsx:381
- frontend/src/pages/ThreatsPage.jsx:272