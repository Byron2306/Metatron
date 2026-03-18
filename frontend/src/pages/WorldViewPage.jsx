import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import axios from 'axios';
import GraphWorld from './GraphWorld';
import { useAuth } from '../context/AuthContext';

export const triuneRoles = ['Metatron', 'Michael', 'Loki'];

const rawBackendUrl = process.env.REACT_APP_BACKEND_URL?.trim();
const API = rawBackendUrl ? `${rawBackendUrl}/api` : '/api';

const WORLD_TABS = ['overview', 'graph', 'events'];

const asArray = (value) => (Array.isArray(value) ? value : []);

const normalizeRisk = (value) => {
  if (typeof value !== 'number' || Number.isNaN(value)) return 0;
  return value <= 1 ? Math.round(value * 100) : Math.max(0, Math.min(100, Math.round(value)));
};

const riskBadge = (value) => {
  if (value >= 80) return 'text-red-300 bg-red-500/20 border-red-500/40';
  if (value >= 60) return 'text-orange-300 bg-orange-500/20 border-orange-500/40';
  if (value >= 40) return 'text-yellow-300 bg-yellow-500/20 border-yellow-500/40';
  return 'text-emerald-300 bg-emerald-500/20 border-emerald-500/40';
};

const humanizeReason = (reason) => {
  if (!reason) return 'based on current telemetry';
  return String(reason).replaceAll('_', ' ');
};

const humanizeAction = (action) => {
  const verb = action?.action ? String(action.action).replaceAll('_', ' ') : 'investigate';
  const target = action?.entity_id || action?.target || 'target entity';
  return `${verb} on ${target} (${humanizeReason(action?.reason)})`;
};

const humanizeHypothesis = (hypothesis) => {
  const candidate = hypothesis?.candidate || hypothesis?.title || 'unknown hypothesis';
  const score = hypothesis?.score;
  const confidence =
    typeof score === 'number'
      ? `${score <= 1 ? Math.round(score * 100) : Math.round(score)}% confidence`
      : 'confidence pending';
  return `${candidate} — ${confidence}`;
};

const formatEventLine = (event) => {
  const type = event?.type || event?.event_type || 'event';
  const name = event?.attributes?.name || event?.id || event?.entity_id || 'unknown entity';
  return `${type}: ${name}`;
};

export default function WorldViewPage() {
  const { getAuthHeaders } = useAuth();
  const [state, setState] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchParams, setSearchParams] = useSearchParams();

  const tabParam = searchParams.get('tab') || 'overview';
  const activeTab = WORLD_TABS.includes(tabParam) ? tabParam : 'overview';

  useEffect(() => {
    const fetchState = async () => {
      try {
        const res = await axios.get(`${API}/metatron/state`, {
          headers: getAuthHeaders(),
        });
        setState(res.data);
      } catch (err) {
        console.error('Failed to fetch metatron state', err);
      } finally {
        setLoading(false);
      }
    };
    fetchState();
  }, [getAuthHeaders]);

  if (loading) {
    return <p>Loading Metatron page...</p>;
  }

  const h = state?.header || {};
  const n = state?.narrative || {};
  const actions = Array.isArray(state?.actions) ? state.actions : [];
  const hypotheses = Array.isArray(state?.hypotheses) ? state.hypotheses : [];
  const hotspots = Array.isArray(state?.hotspots) ? state.hotspots : [];
  const timeline = Array.isArray(state?.timeline) ? state.timeline : [];
  const recentEvents = asArray(state?.recent_events).length ? asArray(state?.recent_events) : timeline;
  const attackPath = state?.attack_path || {};
  const attackNodes = asArray(attackPath?.nodes);
  const attackEdges = asArray(attackPath?.edges);
  const trustEntries = Object.entries(state?.trust || {});

  const setTab = (tabName) => {
    const next = new URLSearchParams(searchParams);
    if (tabName === 'overview') {
      next.delete('tab');
    } else {
      next.set('tab', tabName);
    }
    setSearchParams(next, { replace: true });
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 rounded-xl flex items-center justify-center bg-gradient-to-br from-indigo-600 via-cyan-500 to-emerald-500 shadow-lg" />
          <div>
            <h2 className="text-2xl font-bold text-white">World View</h2>
            <p className="text-sm text-slate-300">
              Natural-language posture summary with live graph, hotspots, and response priorities.
            </p>
          </div>
        </div>
        <div className="inline-flex rounded-lg p-1 gap-1 bg-slate-900/70 border border-slate-700">
          {WORLD_TABS.map((tab) => {
            const selected = activeTab === tab;
            return (
              <button
                key={tab}
                type="button"
                onClick={() => setTab(tab)}
                className="px-3 py-1.5 rounded-md text-sm capitalize transition-colors"
                style={
                  selected
                    ? { background: 'linear-gradient(90deg,#22d3ee,#34d399)', color: '#042A2B', fontWeight: 700 }
                    : { color: '#A5F3FC', background: 'transparent' }
                }
              >
                {tab}
              </button>
            );
          })}
        </div>
      </div>

      {activeTab === 'graph' ? (
        <div className="card p-4">
          <GraphWorld embedded initialState={state} />
        </div>
      ) : null}

      {activeTab === 'overview' ? (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-4">
            {[
              { label: 'Risk Level', value: h.risk_level },
              { label: 'Active Campaigns', value: h.active_campaigns },
              { label: 'High-Risk Identities', value: h.high_risk_identities },
              { label: 'Critical Hosts', value: h.critical_hosts },
              { label: 'Containments', value: h.active_containments },
              { label: 'Trust Drift', value: h.trust_drift || state?.trust?.identity || '-' },
              { label: 'ML Confidence', value: h.ml_confidence || '-' },
            ].map((metric, idx) => (
              <div key={idx} className="p-4 rounded-xl shadow-md bg-gradient-to-tr from-slate-900 to-slate-800 border border-slate-700">
                <div className="text-xs text-slate-400">{metric.label}</div>
                <div className="text-lg font-semibold text-cyan-100">{String(metric.value ?? '-')}</div>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <section className="card p-4 border border-slate-700 bg-gradient-to-br from-slate-900 to-slate-800">
              <h3 className="font-semibold text-lg text-cyan-100">Metatron Narrative</h3>
              <p className="text-sm mt-2 text-slate-300">
                {state?.metatron_summary ||
                  n.summary ||
                  n.objective ||
                  state?.summary ||
                  'Metatron is collecting fresh telemetry and building context.'}
              </p>
              <div className="mt-3 text-xs text-slate-400">Trust signals</div>
              <div className="mt-2 flex flex-wrap gap-2">
                {(trustEntries.length ? trustEntries : [['status', 'unknown']]).map(([key, value]) => (
                  <span key={key} className="px-2 py-1 rounded-md border border-slate-600 bg-slate-900/70 text-xs text-slate-200">
                    {key}: {String(value)}
                  </span>
                ))}
              </div>
            </section>

            <section className="card p-4 border border-cyan-900/40 bg-slate-900/70">
              <h3 className="font-semibold text-lg text-cyan-100">Michael Recommendations</h3>
              {actions.length ? (
                <ul className="space-y-2 mt-2 text-sm">
                  {actions.map((action, idx) => (
                    <li key={idx} className="rounded-lg p-2 bg-slate-800/70 border border-slate-700">
                      {humanizeAction(action)}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm mt-2 text-slate-300">No immediate response actions are required.</p>
              )}
            </section>

            <section className="card p-4 border border-violet-900/40 bg-slate-900/70">
              <h3 className="font-semibold text-lg text-cyan-100">Loki Hypotheses</h3>
              {hypotheses.length ? (
                <ol className="space-y-2 mt-2 text-sm">
                  {hypotheses.map((hypothesis, idx) => (
                    <li key={idx} className="rounded-lg p-2 bg-slate-800/70 border border-slate-700">
                      {humanizeHypothesis(hypothesis)}
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="text-sm mt-2 text-slate-300">No active hypotheses currently ranked.</p>
              )}
            </section>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <section className="card p-4 border border-slate-700 bg-slate-900/70">
              <h3 className="font-semibold text-cyan-100">Attack Path Summary</h3>
              <div className="mt-3 grid grid-cols-2 gap-3">
                <div className="rounded-lg p-3 bg-slate-800/80 border border-slate-700">
                  <div className="text-xs text-slate-400">Graph Nodes</div>
                  <div className="text-xl font-semibold text-white">{attackNodes.length}</div>
                </div>
                <div className="rounded-lg p-3 bg-slate-800/80 border border-slate-700">
                  <div className="text-xs text-slate-400">Graph Edges</div>
                  <div className="text-xl font-semibold text-white">{attackEdges.length}</div>
                </div>
              </div>
              <div className="mt-3 space-y-2 text-sm">
                {attackEdges.slice(0, 5).map((edge, idx) => (
                  <div key={idx} className="rounded p-2 bg-slate-800/60 border border-slate-700 text-slate-200">
                    {edge.source} → {edge.target} ({edge.relation || 'related'})
                  </div>
                ))}
                {attackEdges.length === 0 ? (
                  <p className="text-slate-300">No connected attack path is established yet; graph will fill as relationships are ingested.</p>
                ) : null}
              </div>
            </section>

            <section className="card p-4 border border-slate-700 bg-slate-900/70">
              <h3 className="font-semibold text-cyan-100">Entity Hotspots</h3>
              <div className="mt-2 space-y-2">
                {hotspots.length ? (
                  hotspots.slice(0, 8).map((entity, idx) => {
                    const score = normalizeRisk(entity?.attributes?.risk_score ?? entity?.risk_score ?? 0);
                    return (
                      <div key={entity.id || idx} className="rounded-lg p-3 bg-slate-800/80 border border-slate-700">
                        <div className="flex items-center justify-between">
                          <div className="text-sm text-white">{entity.id || `entity-${idx}`}</div>
                          <span className={`text-xs px-2 py-1 rounded border ${riskBadge(score)}`}>{score}</span>
                        </div>
                        <div className="text-xs text-slate-400 mt-1">{entity.type || 'entity'}</div>
                      </div>
                    );
                  })
                ) : (
                  <p className="text-sm text-slate-300">No high-risk hotspots were reported in this snapshot.</p>
                )}
              </div>
            </section>
          </div>

          <div className="card p-4 border border-slate-700 bg-gradient-to-r from-slate-900 to-slate-800">
            <h3 className="font-semibold text-cyan-100">What this means right now</h3>
            <p className="mt-2 text-sm text-slate-300">
              Current posture is <span className="text-cyan-200 font-semibold">{String(h.risk_level || 'unknown')}</span>.
              {' '}Metatron sees <span className="text-cyan-200 font-semibold">{hotspots.length}</span> hotspot entities,
              {' '}<span className="text-cyan-200 font-semibold">{actions.length}</span> recommended responses,
              {' '}and <span className="text-cyan-200 font-semibold">{hypotheses.length}</span> active hypotheses.
              {' '}Last state change: {h.last_state_change || 'not yet recorded'}.
            </p>
          </div>
        </>
      ) : null}

      {activeTab === 'events' ? (
        <div className="space-y-4">
          <section className="card p-4 border border-slate-700 bg-slate-900/70">
            <h3 className="font-semibold text-cyan-100">World Events</h3>
            {recentEvents.length ? (
              <ol className="mt-3 space-y-2">
                {recentEvents.slice(0, 40).map((event, idx) => (
                  <li key={idx} className="rounded-lg p-3 bg-slate-800/80 border border-slate-700">
                    <div className="text-sm text-white">{formatEventLine(event)}</div>
                    <div className="text-xs text-slate-400 mt-1">
                      {event?.timestamp || event?.last_seen || event?.first_seen || 'time unavailable'}
                    </div>
                  </li>
                ))}
              </ol>
            ) : (
              <p className="text-sm text-slate-300 mt-2">No recent world events provided in the current snapshot.</p>
            )}
          </section>

          <section className="card p-4 border border-slate-700 bg-slate-900/70">
            <h3 className="font-semibold text-cyan-100">Evidence Timeline</h3>
            {timeline.length ? (
              <ol className="mt-3 space-y-2">
                {timeline.map((entry, idx) => (
                  <li key={idx} className="rounded-lg p-3 bg-slate-800/80 border border-slate-700">
                    <div className="text-sm text-white">{formatEventLine(entry)}</div>
                    <div className="text-xs text-slate-400 mt-1">
                      {entry?.last_seen || entry?.first_seen || entry?.timestamp || 'time unavailable'}
                    </div>
                  </li>
                ))}
              </ol>
            ) : (
              <p className="text-sm text-slate-300">No evidence timeline entries have been produced yet.</p>
            )}
          </section>
        </div>
      ) : null}
    </div>
  );
}
