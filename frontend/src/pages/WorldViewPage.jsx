import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import axios from 'axios';
import GraphWorld from './GraphWorld';
import { useAuth } from '../context/AuthContext';

export const triuneRoles = ['Metatron', 'Michael', 'Loki'];

const rawBackendUrl = process.env.REACT_APP_BACKEND_URL?.trim();
const API = rawBackendUrl ? `${rawBackendUrl}/api` : '/api';

const WORLD_TABS = ['overview', 'graph', 'events'];

export default function WorldViewPage() {
  const { token } = useAuth();
  const [state, setState] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchParams, setSearchParams] = useSearchParams();

  const tabParam = searchParams.get('tab') || 'overview';
  const activeTab = WORLD_TABS.includes(tabParam) ? tabParam : 'overview';

  useEffect(() => {
    const fetchState = async () => {
      try {
        const res = await axios.get(`${API}/metatron/state`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        setState(res.data);
      } catch (err) {
        console.error('Failed to fetch metatron state', err);
      } finally {
        setLoading(false);
      }
    };
    fetchState();
  }, [token]);

  if (loading) {
    return <p>Loading Metatron page...</p>;
  }

  const h = state?.header || {};
  const n = state?.narrative || {};
  const actions = Array.isArray(state?.actions) ? state.actions : [];
  const hypotheses = Array.isArray(state?.hypotheses) ? state.hypotheses : [];
  const hotspots = Array.isArray(state?.hotspots) ? state.hotspots : [];
  const timeline = Array.isArray(state?.timeline) ? state.timeline : [];
  const recentEvents = Array.isArray(state?.recent_events) ? state.recent_events : [];

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
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 rounded-xl flex items-center justify-center bg-gradient-to-br from-indigo-600 to-sky-500 shadow-lg">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-8 w-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8c-3.866 0-7 3.134-7 7 0 1.657.672 3.157 1.757 4.243A5 5 0 0012 20a5 5 0 005-5c0-3.866-3.134-7-7-7z" /></svg>
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white">Metatron - State of the Defended Universe</h2>
            <p className="text-sm text-slate-400">Live situational awareness and attack surface mapping</p>
          </div>
        </div>
        <div className="inline-flex rounded-lg p-1 gap-1" style={{ backgroundColor: 'rgba(15, 23, 42, 0.7)' }}>
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
                    ? { background: 'linear-gradient(90deg,#06b6d4,#0ea5a4)', color: '#042A2B', fontWeight: 700 }
                    : { color: '#A5F3FC' }
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
          {/* Global State Header */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-4">
            {[
              { label: 'Risk Level', value: h.risk_level },
              { label: 'Active Campaigns', value: h.active_campaigns },
              { label: 'High-Risk Identities', value: h.high_risk_identities },
              { label: 'Critical Hosts', value: h.critical_hosts },
              { label: 'Containments', value: h.active_containments },
              { label: 'Deception', value: h.deception_interactions },
              { label: 'Last Change', value: h.last_state_change || '-' },
              { label: 'Trust Drift', value: h.trust_drift },
              { label: 'ML Confidence', value: h.ml_confidence },
            ].map((metric, idx) => (
              <div key={idx} className="p-4 rounded-lg shadow-md bg-gradient-to-tr from-slate-800 to-slate-900 border border-slate-700">
                <div className="text-xs text-slate-400">{metric.label}</div>
                <div className="text-lg font-semibold text-white">{String(metric.value || '-')}</div>
              </div>
            ))}
          </div>

          {/* Three-pane area: Metatron | Michael | Loki */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <section className="card p-4">
              <h3 className="font-semibold text-lg">Metatron - System Thoughts</h3>
              <div className="text-sm mt-2">
                <div>
                  <strong>Risk:</strong> {h.risk_level || '-'}
                </div>
                <div>
                  <strong>Last change:</strong> {h.last_state_change || '-'}
                </div>
                <div className="mt-2 text-xs text-slate-400">Summary:</div>
                <div className="mt-1 text-sm">
                  {state?.metatron_summary || n.objective || state?.summary || 'No summary available.'}
                </div>
                <div className="mt-3 text-xs text-slate-400">Trust Snapshot</div>
                <pre className="text-xs mt-1" style={{ maxHeight: 120, overflow: 'auto' }}>
                  {JSON.stringify(state?.trust || {}, null, 2)}
                </pre>
              </div>
            </section>

            <section className="card p-4">
              <h3 className="font-semibold text-lg">Michael - Recommended Actions</h3>
              {actions.length ? (
                <ul className="list-disc list-inside ml-4 mt-2 text-sm">
                  {actions.map((action, idx) => (
                    <li key={idx}>{action.title || JSON.stringify(action)}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm mt-2">No recommended actions right now.</p>
              )}
              <div className="mt-3">
                <button className="px-3 py-2 rounded-md shadow-sm" style={{ background: '#0ea5a4', color: '#042A2B' }}>
                  Execute Selected
                </button>
              </div>
            </section>

            <section className="card p-4">
              <h3 className="font-semibold text-lg">Loki - Hypotheses</h3>
              {hypotheses.length ? (
                <ol className="list-decimal list-inside ml-4 mt-2 text-sm">
                  {hypotheses.map((hypothesis, idx) => (
                    <li key={idx}>{hypothesis.title || JSON.stringify(hypothesis)}</li>
                  ))}
                </ol>
              ) : (
                <p className="text-sm mt-2">No active hypotheses.</p>
              )}
              <div className="mt-3 text-xs text-slate-400">Confidence signals:</div>
              <div className="mt-1 text-sm">
                <pre className="text-xs">{JSON.stringify(state?.hypothesis_confidence || {}, null, 2)}</pre>
              </div>
            </section>
          </div>

          {/* Attack Path Risk Map (full view) */}
          <div className="mt-4 card p-4">
            <h3 className="font-semibold">Attack Path Risk Map</h3>
            <div className="mt-3 bg-slate-900 rounded-md p-4 text-xs overflow-auto" style={{ minHeight: 180 }}>
              <pre className="text-xs">{JSON.stringify(state?.attack_path, null, 2)}</pre>
            </div>
          </div>

          {/* Trust State & Entity Hotspots */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <section className="card p-4">
              <h3 className="font-semibold">Trust State</h3>
              <pre className="text-xs">{JSON.stringify(state?.trust || {}, null, 2)}</pre>
            </section>
            <section className="card p-4">
              <h3 className="font-semibold">Entity Hotspots</h3>
              {hotspots.length ? (
                <ul className="list-disc list-inside">
                  {hotspots.map((entity, idx) => (
                    <li key={idx}>{JSON.stringify(entity)}</li>
                  ))}
                </ul>
              ) : (
                <p>None</p>
              )}
            </section>
          </div>
        </>
      ) : null}

      {activeTab === 'events' ? (
        <div className="space-y-4">
          <section className="card p-4">
            <h3 className="font-semibold">World Events</h3>
            {recentEvents.length ? (
              <ol className="list-decimal list-inside space-y-2">
                {recentEvents.map((event, idx) => (
                  <li key={idx} className="text-sm">
                    {JSON.stringify(event)}
                  </li>
                ))}
              </ol>
            ) : (
              <p className="text-sm text-slate-300">No recent world events provided in the snapshot.</p>
            )}
          </section>

          <section className="card p-4">
            <h3 className="font-semibold">Evidence Timeline</h3>
            {timeline.length ? (
              <ol className="list-decimal list-inside">
                {timeline.map((entry, idx) => (
                  <li key={idx}>{JSON.stringify(entry)}</li>
                ))}
              </ol>
            ) : (
              <p>Empty</p>
            )}
          </section>
        </div>
      ) : null}
    </div>
  );
}
