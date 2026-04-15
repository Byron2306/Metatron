# Full Pages Wiring + Capability Audit (Updated)

Generated: 2026-04-15  
Method: static repository scan (`frontend/src/pages` and backend router inventory).

---

## Current Counts

- Frontend page files scanned (`.jsx/.tsx`, excluding test files): **69**
- Pages with detected API call sites: **58**
- Pages with zero direct API calls: **11**
- Total frontend API call sites detected: **339**
- Backend router files scanned (`backend/routers/*.py`, excluding `dependencies.py`): **61**
- Backend endpoint decorators detected (`@router.get/post/put/delete/patch`): **694**

> Note: workspace/container pages often have zero direct API calls by design because child tab components perform data fetching.

---

## Pages with Zero Direct API Calls

- `frontend/src/pages/AIActivityWorkspacePage.jsx`
- `frontend/src/pages/CommandWorkspacePage.jsx`
- `frontend/src/pages/DetectionEngineeringWorkspacePage.jsx`
- `frontend/src/pages/EmailSecurityWorkspacePage.jsx`
- `frontend/src/pages/EndpointMobilityWorkspacePage.jsx`
- `frontend/src/pages/GraphWorld.jsx`
- `frontend/src/pages/InvestigationWorkspacePage.jsx`
- `frontend/src/pages/JobCard.jsx`
- `frontend/src/pages/LoginPage.jsx`
- `frontend/src/pages/ResponseOperationsPage.jsx`
- `frontend/src/pages/WorldGraph.jsx`

---

## Unmatched Call-Site Review

One flagged call-site from static extraction:

- `frontend/src/pages/TimelinePage.jsx:58 -> /api/timelines/recent`

This is **not an actual mismatch**.  
Backend defines `timelines_router` with `prefix="/timelines"` and `@get("/recent")` in `backend/routers/timeline.py`, and server mounts that router under `/api`.

Result: **effective unmatched call-sites = 0 after semantic review**.

---

## Wiring Interpretation

1. Primary frontend-to-backend wiring is broadly aligned.
2. The remaining risk is not endpoint absence, but API construction variance across pages (inline URL construction patterns).
3. Route-level compatibility remains strong due to redirect strategy in `frontend/src/App.js`.

