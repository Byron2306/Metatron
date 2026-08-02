import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import apiClient from '../lib/api';
import GraphWorld from './GraphWorld';
import { useAuth } from '../context/AuthContext';

export const triuneRoles = ['Metatron', 'Michael', 'Loki'];


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
  const refs = Array.isArray(event?.entity_refs) && event.entity_refs.length
    ? event.entity_refs.filter(Boolean).slice(0, 2).join(', ')
    : event?.attributes?.name || event?.id || event?.entity_id || '';
  return refs ? `${type}: ${refs}` : type;
};

const formatEventTime = (event) =>
  event?.created || event?.timestamp || event?.last_seen || event?.first_seen || 'time unavailable';

export default function WorldViewPage() {
  const { getAuthHeaders } = useAuth();
  const [state, setState] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchParams, setSearchParams] = useSearchParams();

  const tabParam = searchParams.get('tab') || 'overview';
  const activeTab = WORLD_TABS.includes(tabParam) ? tabParam : 'overview';

  useEffect(() => {
    let cancelled = false;
    const fetchState = async () => {
      try {
        const res = await apiClient.get(`/metatron/state?lite=true`, {
          headers: getAuthHeaders(),
        });
        if (!cancelled) setState(res.data);
      } catch (err) {
        console.error('Failed to fetch metatron state', err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    fetchState();
    const id = setInterval(fetchState, 12000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
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
  const recentEvents = asArray(state?.recent_events).length
    ? asArray(state?.recent_events)
    : timeline;
  const attackPath = state?.attack_path || {};
  const attackNodes = asArray(attackPath?.nodes);
  const attackEdges = asArray(attackPath?.edges);
  const trustEntries = Object.entries(state?.trust || {});
  const worldStateHash = state?.world_state_hash || state?.header?.world_state_hash || state?.snapshot?.world_state_hash || null;
  const manifoldVersion = state?.snapshot_version || state?.header?.snapshot_version || null;
  const narrativeFields = {
    summary: state?.metatron_summary || n.summary || state?.summary || null,
    objective: n.objective || null,
    campaign: n.campaign_id || null,
  };
  const authoritativeFields = {
    riskLevel: h.risk_level || 'unknown',
    trustDrift: h.trust_drift || state?.trust?.identity || 'unknown',
    mlConfidence: h.ml_confidence != null && h.ml_confidence !== 0 ? `${Math.round(h.ml_confidence * 100)}%` : '—',
    actions: actions.length,
    hypotheses: hypotheses.length,
    hotspots: hotspots.length,
    worldStateHash: worldStateHash ? `${String(worldStateHash).slice(0, 18)}...` : 'unavailable',
  };

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
    <div className="p-6 lg:p-8 space-y-6 max-w-7xl mx-auto relative">
      {/* Animated triune sigil ribbon */}
      <div
        aria-hidden="true"
        style={{
          position: 'absolute',
          top: -10,
          left: 0,
          right: 0,
          height: 1,
          background: 'linear-gradient(90deg, transparent, #00f0ff, #bc13fe, #ff2bd6, transparent)',
          opacity: 0.55,
          filter: 'blur(0.4px)',
        }}
      />

      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="flex items-center gap-4">
          <div
            className="relative w-16 h-16 flex items-center justify-center"
            style={{
              background:
                'conic-gradient(from 0deg at 50% 50%, #00f0ff, #7c3aed, #ff2bd6, #39ff14, #00f0ff)',
              boxShadow: '0 0 28px rgba(0,240,255,0.5), 0 0 60px rgba(188,19,254,0.3)',
              clipPath:
                'polygon(50% 0, 100% 25%, 100% 75%, 50% 100%, 0 75%, 0 25%)',
              animation: 'seraph-loader-spin 22s linear infinite',
            }}
          >
            <span
              style={{
                position: 'absolute',
                inset: 4,
                background: '#02050d',
                clipPath:
                  'polygon(50% 0, 100% 25%, 100% 75%, 50% 100%, 0 75%, 0 25%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontFamily: "'Orbitron', monospace",
                fontWeight: 900,
                color: '#00f0ff',
                fontSize: 22,
                textShadow: '0 0 12px rgba(0,240,255,0.7)',
              }}
            >
              Σ
            </span>
          </div>
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="seraph-pip seraph-pip--pink" />
              <span
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 10,
                  letterSpacing: '0.4em',
                  color: '#ff8ad9',
                  textTransform: 'uppercase',
                  textShadow: '0 0 8px rgba(255,43,214,0.5)',
                }}
              >
                METATRON · MICHAEL · LOKI
              </span>
            </div>
            <h2
              className="seraph-gradient-text"
              style={{
                fontFamily: "'Orbitron', sans-serif",
                fontWeight: 900,
                fontSize: 'clamp(2rem, 4vw, 3rem)',
                letterSpacing: '0.06em',
                lineHeight: 1,
                textTransform: 'uppercase',
                margin: 0,
              }}
            >
              World View
            </h2>
            <p
              className="text-sm mt-2"
              style={{
                color: '#b8d8e6',
                fontFamily: "'JetBrains Mono', monospace",
                letterSpacing: '0.04em',
              }}
            >
              &gt; natural-language posture · live graph · hotspots · response priorities
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <div
            className="flex items-center gap-2 px-3 py-1.5"
            style={{
              background: 'linear-gradient(90deg, rgba(57,255,20,0.12), rgba(57,255,20,0.04))',
              border: '1px solid rgba(57,255,20,0.4)',
              boxShadow: '0 0 14px rgba(57,255,20,0.18)',
              clipPath: 'polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px)',
            }}
          >
            <span className="seraph-pip seraph-pip--green" style={{ width: 7, height: 7 }} />
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: '#7fffa6', letterSpacing: '0.32em' }}>
              LIVE · {new Date().toLocaleTimeString()}
            </span>
          </div>

        <div
          className="inline-flex p-1 gap-1"
          style={{
            background: 'rgba(2,8,19,0.7)',
            border: '1px solid rgba(0,240,255,0.32)',
            boxShadow: 'inset 0 0 12px rgba(0,240,255,0.05)',
            clipPath: 'polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px)',
          }}
        >
          {WORLD_TABS.map((tab) => {
            const selected = activeTab === tab;
            return (
              <button
                key={tab}
                type="button"
                onClick={() => setTab(tab)}
                className="px-4 py-2 transition-all"
                style={{
                  fontFamily: "'Orbitron', monospace",
                  fontSize: 11,
                  fontWeight: 700,
                  letterSpacing: '0.18em',
                  textTransform: 'uppercase',
                  background: selected
                    ? 'linear-gradient(135deg, rgba(0,240,255,0.25), rgba(188,19,254,0.18))'
                    : 'transparent',
                  color: selected ? '#ffffff' : '#aef0ff',
                  border: selected ? '1px solid var(--neon-cyan)' : '1px solid transparent',
                  boxShadow: selected
                    ? '0 0 14px rgba(0,240,255,0.45), inset 0 0 10px rgba(0,240,255,0.1)'
                    : 'none',
                  textShadow: selected ? '0 0 8px rgba(0,240,255,0.6)' : 'none',
                  cursor: 'pointer',
                }}
              >
                {tab}
              </button>
            );
          })}
        </div>
        </div>
      </div>

      {activeTab === 'graph' ? (
        <div className="card p-4">
          <GraphWorld embedded initialState={state} />
        </div>
      ) : null}

      {activeTab === 'overview' ? (
        <>
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
            <section
              className="seraph-corner-brackets relative p-4 xl:col-span-2"
              style={{
                background: 'linear-gradient(155deg, rgba(8,22,40,0.96), rgba(4,10,22,0.98))',
                border: '1px solid rgba(0,240,255,0.34)',
                boxShadow: 'inset 0 0 18px rgba(0,240,255,0.05), 0 0 20px rgba(0,240,255,0.08)',
              }}
            >
              <span className="seraph-corner-tl" />
              <span className="seraph-corner-tr" />
              <span className="seraph-corner-bl" />
              <span className="seraph-corner-br" />
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <div className="text-[10px] uppercase" style={{ color: '#00f0ff', fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.32em' }}>
                    Authoritative Control State
                  </div>
                  <div className="mt-3 space-y-2 text-sm">
                    {[
                      ['Risk level', authoritativeFields.riskLevel],
                      ['Trust drift', authoritativeFields.trustDrift],
                      ['ML confidence', authoritativeFields.mlConfidence],
                      ['Hotspots', authoritativeFields.hotspots],
                      ['Recommended actions', authoritativeFields.actions],
                      ['Hypotheses', authoritativeFields.hypotheses],
                      ['World-state hash', authoritativeFields.worldStateHash],
                    ].map(([label, value]) => (
                      <div key={label} className="flex items-center justify-between gap-3 rounded-lg border border-slate-800 bg-slate-900/45 px-3 py-2">
                        <span className="text-slate-400">{label}</span>
                        <span className="text-cyan-100 font-medium">{String(value)}</span>
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] uppercase" style={{ color: '#ff8ad9', fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.32em' }}>
                    Strategic Narrative Layer
                  </div>
                  <div className="mt-3 space-y-3 text-sm">
                    <div className="rounded-lg border border-fuchsia-900/50 bg-fuchsia-500/5 p-3">
                      <div className="text-fuchsia-200 font-semibold">Summary</div>
                      <p className="mt-1 text-slate-200">
                        {narrativeFields.summary || 'Metatron has not published a narrative summary for this snapshot yet.'}
                      </p>
                    </div>
                    <div className="rounded-lg border border-fuchsia-900/50 bg-fuchsia-500/5 p-3">
                      <div className="text-fuchsia-200 font-semibold">Objective</div>
                      <p className="mt-1 text-slate-200">{narrativeFields.objective || 'No explicit strategic objective attached to the current state.'}</p>
                    </div>
                    <div className="rounded-lg border border-fuchsia-900/50 bg-fuchsia-500/5 p-3">
                      <div className="text-fuchsia-200 font-semibold">Campaign Reference</div>
                      <p className="mt-1 text-slate-200">{narrativeFields.campaign || 'No active campaign id published in narrative fields.'}</p>
                    </div>
                  </div>
                </div>
              </div>
            </section>

            <section
              className="seraph-corner-brackets relative p-4"
              style={{
                background: 'linear-gradient(155deg, rgba(16,18,40,0.94), rgba(5,10,22,0.98))',
                border: '1px solid rgba(188,19,254,0.34)',
                boxShadow: 'inset 0 0 18px rgba(188,19,254,0.06), 0 0 20px rgba(188,19,254,0.1)',
              }}
            >
              <span className="seraph-corner-tl" />
              <span className="seraph-corner-tr" />
              <span className="seraph-corner-bl" />
              <span className="seraph-corner-br" />
              <div className="text-[10px] uppercase" style={{ color: '#d8a8ff', fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.32em' }}>
                Manifold Integrity
              </div>
              <div className="mt-3 space-y-3 text-sm">
                <div className="rounded-lg border border-purple-900/60 bg-purple-500/5 p-3">
                  <div className="text-purple-200 font-semibold">World-state binding</div>
                  <p className="mt-1 text-slate-200">
                    {worldStateHash ? 'This snapshot is carrying a concrete world-state hash.' : 'No world-state hash is published in this snapshot.'}
                  </p>
                </div>
                <div className="rounded-lg border border-purple-900/60 bg-purple-500/5 p-3">
                  <div className="text-purple-200 font-semibold">Snapshot version</div>
                  <p className="mt-1 text-slate-200">{manifoldVersion || 'Version not published'}</p>
                </div>
                <div className="rounded-lg border border-purple-900/60 bg-purple-500/5 p-3">
                  <div className="text-purple-200 font-semibold">Interpretation boundary</div>
                  <p className="mt-1 text-slate-200">
                    Narrative fields are informative. Trust dimensions, risk posture, and manifold binding are the authoritative control plane.
                  </p>
                </div>
              </div>
            </section>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Risk Level', value: h.risk_level ?? 'unknown', highlight: (h.risk_level === 'elevated' || h.risk_level === 'critical') },
              { label: 'Online Agents', value: h.online_agents != null ? `${h.online_agents} / ${h.total_agents ?? '?'}` : '-' },
              { label: 'Critical Hosts', value: h.critical_hosts ?? 0 },
              { label: 'Active Campaigns', value: h.active_campaigns ?? 0 },
              { label: 'High-Risk Identities', value: h.high_risk_identities ?? 0 },
              { label: 'Containments', value: h.active_containments ?? 0 },
              { label: 'Trust Drift', value: h.trust_drift || state?.trust?.identity || 'stable' },
              { label: 'ML Confidence', value: h.ml_confidence != null && h.ml_confidence !== 0 ? `${Math.round(h.ml_confidence * 100)}%` : '—' },
            ].map((metric, idx) => {
              const label = metric.label.toLowerCase();
              const isRisk = label.includes('risk level');
              const isOnlineAgents = label.includes('online agents');
              const accent = metric.highlight
                ? { border: 'rgba(255,76,128,0.7)', glow: 'rgba(255,76,128,0.42)', text: '#ff9cb8', bar: 'linear-gradient(90deg, rgba(255,76,128,0.95), rgba(255,43,214,0.9))' }
                : isOnlineAgents
                  ? { border: 'rgba(57,255,20,0.62)', glow: 'rgba(57,255,20,0.32)', text: '#b6ffb7', bar: 'linear-gradient(90deg, rgba(57,255,20,0.92), rgba(0,240,255,0.85))' }
                  : isRisk
                    ? { border: 'rgba(255,43,214,0.62)', glow: 'rgba(255,43,214,0.3)', text: '#ffb8ef', bar: 'linear-gradient(90deg, rgba(255,43,214,0.92), rgba(188,19,254,0.9))' }
                    : { border: 'rgba(0,240,255,0.44)', glow: 'rgba(0,240,255,0.2)', text: '#c8f6ff', bar: 'linear-gradient(90deg, rgba(0,240,255,0.88), rgba(125,211,252,0.8))' };

              return (
                <div
                  key={idx}
                  className="p-4 rounded-xl border"
                  style={{
                    background: isRisk || isOnlineAgents
                      ? 'linear-gradient(155deg, rgba(10,24,44,0.92), rgba(5,12,24,0.97))'
                      : 'linear-gradient(155deg, rgba(12,22,38,0.86), rgba(7,14,26,0.95))',
                    borderColor: accent.border,
                    boxShadow: `0 0 0 1px rgba(6,12,24,0.7) inset, 0 0 18px ${accent.glow}`,
                    position: 'relative',
                    overflow: 'hidden',
                  }}
                >
                  <div
                    aria-hidden="true"
                    style={{
                      position: 'absolute',
                      top: 0,
                      left: 0,
                      right: 0,
                      height: 2,
                      background: accent.bar,
                      opacity: 0.95,
                    }}
                  />
                  <div
                    className="text-[11px] uppercase"
                    style={{
                      color: 'rgba(183, 219, 236, 0.86)',
                      letterSpacing: '0.12em',
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    {metric.label}
                  </div>
                  <div
                    className="text-lg font-semibold mt-1"
                    style={{
                      color: accent.text,
                      textShadow: `0 0 10px ${accent.glow}`,
                      fontFamily: "'Orbitron', monospace",
                    }}
                  >
                    {String(metric.value)}
                  </div>
                </div>
              );
            })}
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
            <section className="card p-4 border border-slate-700 bg-slate-900/70">
              <h3 className="font-semibold text-cyan-100">Governance Consequences</h3>
              <div className="mt-3 space-y-2 text-sm">
                <div className="rounded-lg p-3 bg-slate-800/80 border border-slate-700 text-slate-200">
                  {actions.length
                    ? `${actions.length} response actions are recommended from the current world snapshot.`
                    : 'No immediate executor-facing responses are currently recommended.'}
                </div>
                <div className="rounded-lg p-3 bg-slate-800/80 border border-slate-700 text-slate-200">
                  {hypotheses.length
                    ? `${hypotheses.length} ranked hypotheses are shaping triune interpretation of this state.`
                    : 'No ranked triune hypotheses have been published yet.'}
                </div>
                <div className="rounded-lg p-3 bg-slate-800/80 border border-slate-700 text-slate-200">
                  {worldStateHash
                    ? 'This view is suitable for downstream governed action because a world-state hash is present.'
                    : 'Treat this snapshot as informational until a world-state hash is attached.'}
                </div>
              </div>
            </section>

            <section className="card p-4 border border-slate-700 bg-slate-900/70">
              <h3 className="font-semibold text-cyan-100">Trust Dimensions</h3>
              <div className="mt-3 flex flex-wrap gap-2">
                {(trustEntries.length ? trustEntries : [['status', 'unknown']]).map(([key, value]) => (
                  <span
                    key={key}
                    className="text-xs px-3 py-2 rounded-lg border"
                    style={{
                      borderColor: 'rgba(0,240,255,0.28)',
                      background: 'rgba(0,240,255,0.06)',
                      color: '#c8f6ff',
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    {key}: {String(value)}
                  </span>
                ))}
              </div>
            </section>

            <section className="card p-4 border border-slate-700 bg-slate-900/70">
              <h3 className="font-semibold text-cyan-100">Triune Output Quality</h3>
              <div className="mt-3 space-y-2 text-sm">
                <div className="rounded-lg p-3 bg-slate-800/80 border border-slate-700 text-slate-200">
                  Michael actions: <span className="text-green-300 font-semibold">{actions.length}</span>
                </div>
                <div className="rounded-lg p-3 bg-slate-800/80 border border-slate-700 text-slate-200">
                  Loki hypotheses: <span className="text-fuchsia-300 font-semibold">{hypotheses.length}</span>
                </div>
                <div className="rounded-lg p-3 bg-slate-800/80 border border-slate-700 text-slate-200">
                  World hotspots: <span className="text-orange-300 font-semibold">{hotspots.length}</span>
                </div>
              </div>
            </section>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Metatron — cyan */}
            <section
              className="seraph-corner-brackets relative p-4"
              style={{
                background: 'linear-gradient(160deg, rgba(0,240,255,0.06), rgba(2,8,19,0.94))',
                border: '1px solid rgba(0,240,255,0.4)',
                borderTop: '2px solid var(--neon-cyan)',
                boxShadow: 'inset 0 0 18px rgba(0,240,255,0.05), 0 0 18px rgba(0,240,255,0.08)',
              }}
            >
              <span className="seraph-corner-tl" />
              <span className="seraph-corner-tr" />
              <h3
                style={{
                  fontFamily: "'Orbitron', monospace",
                  fontWeight: 800,
                  fontSize: '1.1rem',
                  letterSpacing: '0.16em',
                  textTransform: 'uppercase',
                  color: '#00f0ff',
                  textShadow: '0 0 12px rgba(0,240,255,0.7)',
                  margin: 0,
                }}
              >
                Metatron Narrative
              </h3>
              <p className="text-sm mt-2" style={{ color: '#d7faff', lineHeight: 1.6 }}>
                {state?.metatron_summary ||
                  n.summary ||
                  n.objective ||
                  state?.summary ||
                  'Metatron is collecting fresh telemetry and building context.'}
              </p>
              <div className="mt-3 text-[10px]" style={{ color: 'var(--neon-cyan)', fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.32em', textTransform: 'uppercase' }}>
                Trust signals
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                {(trustEntries.length ? trustEntries : [['status', 'unknown']]).map(([key, value]) => (
                  <span
                    key={key}
                    style={{
                      padding: '3px 10px',
                      border: '1px solid rgba(0,240,255,0.32)',
                      background: 'rgba(0,240,255,0.06)',
                      color: '#aef0ff',
                      fontSize: 11,
                      fontFamily: "'JetBrains Mono', monospace",
                      letterSpacing: '0.06em',
                      clipPath: 'polygon(5px 0, 100% 0, 100% calc(100% - 5px), calc(100% - 5px) 100%, 0 100%, 0 5px)',
                    }}
                  >
                    {key}: {String(value)}
                  </span>
                ))}
              </div>
            </section>

            {/* Michael — green */}
            <section
              className="seraph-corner-brackets relative p-4"
              style={{
                background: 'linear-gradient(160deg, rgba(57,255,20,0.06), rgba(2,8,19,0.94))',
                border: '1px solid rgba(57,255,20,0.4)',
                borderTop: '2px solid #39ff14',
                boxShadow: 'inset 0 0 18px rgba(57,255,20,0.05), 0 0 18px rgba(57,255,20,0.08)',
              }}
            >
              <span style={{ position: 'absolute', top: -1, left: -1, width: 18, height: 18, borderTop: '2px solid #39ff14', borderLeft: '2px solid #39ff14', filter: 'drop-shadow(0 0 6px rgba(57,255,20,0.7))' }} />
              <span style={{ position: 'absolute', top: -1, right: -1, width: 18, height: 18, borderTop: '2px solid #39ff14', borderRight: '2px solid #39ff14', filter: 'drop-shadow(0 0 6px rgba(57,255,20,0.7))' }} />
              <h3
                style={{
                  fontFamily: "'Orbitron', monospace",
                  fontWeight: 800,
                  fontSize: '1.1rem',
                  letterSpacing: '0.16em',
                  textTransform: 'uppercase',
                  color: '#39ff14',
                  textShadow: '0 0 12px rgba(57,255,20,0.7)',
                  margin: 0,
                }}
              >
                Michael Recommendations
              </h3>
              {actions.length ? (
                <ul className="space-y-2 mt-3 text-sm">
                  {actions.map((action, idx) => (
                    <li
                      key={idx}
                      style={{
                        padding: 10,
                        background: 'rgba(57,255,20,0.04)',
                        border: '1px solid rgba(57,255,20,0.22)',
                        borderLeft: '2px solid #39ff14',
                        color: '#d4ffd9',
                      }}
                    >
                      {humanizeAction(action)}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm mt-3" style={{ color: '#b6f5ff' }}>No immediate response actions are required.</p>
              )}
            </section>

            {/* Loki — pink/violet */}
            <section
              className="seraph-corner-brackets relative p-4"
              style={{
                background: 'linear-gradient(160deg, rgba(255,43,214,0.06), rgba(2,8,19,0.94))',
                border: '1px solid rgba(255,43,214,0.4)',
                borderTop: '2px solid var(--neon-pink)',
                boxShadow: 'inset 0 0 18px rgba(255,43,214,0.05), 0 0 18px rgba(255,43,214,0.08)',
              }}
            >
              <span style={{ position: 'absolute', top: -1, left: -1, width: 18, height: 18, borderTop: '2px solid #ff2bd6', borderLeft: '2px solid #ff2bd6', filter: 'drop-shadow(0 0 6px rgba(255,43,214,0.7))' }} />
              <span style={{ position: 'absolute', top: -1, right: -1, width: 18, height: 18, borderTop: '2px solid #ff2bd6', borderRight: '2px solid #ff2bd6', filter: 'drop-shadow(0 0 6px rgba(255,43,214,0.7))' }} />
              <h3
                style={{
                  fontFamily: "'Orbitron', monospace",
                  fontWeight: 800,
                  fontSize: '1.1rem',
                  letterSpacing: '0.16em',
                  textTransform: 'uppercase',
                  color: '#ff2bd6',
                  textShadow: '0 0 12px rgba(255,43,214,0.7)',
                  margin: 0,
                }}
              >
                Loki Hypotheses
              </h3>
              {hypotheses.length ? (
                <ol className="space-y-2 mt-3 text-sm">
                  {hypotheses.map((hypothesis, idx) => (
                    <li
                      key={idx}
                      style={{
                        padding: 10,
                        background: 'rgba(255,43,214,0.04)',
                        border: '1px solid rgba(255,43,214,0.22)',
                        borderLeft: '2px solid #ff2bd6',
                        color: '#fce0f7',
                      }}
                    >
                      {humanizeHypothesis(hypothesis)}
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="text-sm mt-3" style={{ color: '#b6f5ff' }}>No active hypotheses currently ranked.</p>
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
              {state?.metatron_summary
                ? state.metatron_summary
                : <>
                    Current posture is{' '}
                    <span className="text-cyan-200 font-semibold">{String(h.risk_level || 'unknown')}</span>.
                    {' '}Metatron sees{' '}
                    <span className="text-cyan-200 font-semibold">{hotspots.length}</span> hotspot entities,{' '}
                    <span className="text-cyan-200 font-semibold">{actions.length}</span> recommended responses,{' '}
                    and <span className="text-cyan-200 font-semibold">{hypotheses.length}</span> active hypotheses.
                  </>}
            </p>
            {h.last_state_change ? (
              <p className="mt-1 text-xs text-slate-500">Last state change: {h.last_state_change}</p>
            ) : null}
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
                    <div className="text-xs text-slate-400 mt-1">{formatEventTime(event)}</div>
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
                    <div className="text-xs text-slate-400 mt-1">{formatEventTime(entry)}</div>
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
