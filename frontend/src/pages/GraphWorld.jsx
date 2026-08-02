import React, { useEffect, useMemo, useRef, useState } from 'react';
import apiClient from '../lib/api';
import ForceGraph2D from 'react-force-graph-2d';
import { useAuth } from '../context/AuthContext';

export const triuneRoles = ['Metatron', 'Michael', 'Loki'];


const toNodeId = (value) => (value && typeof value === 'object' ? value.id : value);

const ensureArray = (value) => (Array.isArray(value) ? value : []);

const normalizeRiskScore = (value) => {
  if (typeof value !== 'number' || Number.isNaN(value)) return 0;
  if (value <= 1) return Math.round(value * 100);
  return Math.max(0, Math.min(100, Math.round(value)));
};

const inferNodeColor = (riskScore, type) => {
  if (riskScore >= 85) return '#ff3838';
  if (riskScore >= 65) return '#ff8a3c';
  if (riskScore >= 40) return '#ffb020';
  if (type === 'host') return '#00f0ff';
  if (type === 'user') return '#bc13fe';
  if (type === 'campaign') return '#ff2bd6';
  if (type === 'process') return '#7c3aed';
  if (type === 'file') return '#aef0ff';
  return '#39ff14';
};

const mapStateToGraph = (state) => {
  const payload = state || {};
  const attackPath = payload.attack_path || {};
  const entities = ensureArray(payload.entities);
  const hotspots = ensureArray(payload.hotspots);
  const attackNodes = ensureArray(attackPath.nodes);
  const baseNodes = entities.length ? entities : attackNodes.length ? attackNodes : hotspots;

  const nodes = baseNodes.map((entity, idx) => {
    const attributes = entity?.attributes || {};
    const riskScore = normalizeRiskScore(
      entity?.risk_score ?? attributes?.risk_score ?? attributes?.risk ?? 0,
    );
    const nodeType = entity.type || attributes.entity_type || 'entity';
    return {
      id: entity.id || entity._id || `ent:${idx}`,
      name:
        entity.name ||
        attributes.hostname ||
        attributes.host ||
        nodeType ||
        entity.id ||
        `node-${idx}`,
      type: nodeType,
      status: attributes.status,
      riskScore,
      color: inferNodeColor(riskScore, nodeType),
    };
  });

  const nodeIds = new Set(nodes.map((node) => node.id));
  const relationships = ensureArray(payload.relationships).length
    ? ensureArray(payload.relationships)
    : ensureArray(attackPath.edges);

  const links = relationships
    .map((rel) => {
      const source = toNodeId(rel.source || rel.from || rel.src);
      const target = toNodeId(rel.target || rel.to || rel.dst);
      return {
        source,
        target,
        relation: rel.relation || rel.type || 'related_to',
        value: rel.score || rel.weight || 1,
      };
    })
    .filter((rel) => rel.source && rel.target && nodeIds.has(rel.source) && nodeIds.has(rel.target));

  return { nodes, links };
};

const summarizeRelationCounts = (links) => {
  const counts = {};
  for (const link of ensureArray(links)) {
    const key = String(link.relation || 'related_to');
    counts[key] = (counts[key] || 0) + 1;
  }
  return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
};

export default function GraphWorld({ initialState = null, embedded = false }) {
  const { token } = useAuth();
  const [data, setData] = useState({ nodes: [], links: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState('');
  const fgRef = useRef(null);

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    setError(null);

    if (initialState) {
      const graph = mapStateToGraph(initialState);
      if (mounted) {
        setData(graph);
        setLoading(false);
        setTimeout(() => fgRef.current && fgRef.current.zoomToFit(450), 150);
      }
      return () => {
        mounted = false;
      };
    }

    const requestConfig = token ? { headers: { Authorization: `Bearer ${token}` } } : undefined;

    apiClient
      .get(`/metatron/state?lite=true`, requestConfig)
      .then((res) => {
        if (!mounted) {
          return;
        }
        setData(mapStateToGraph(res.data));
        setTimeout(() => fgRef.current && fgRef.current.zoomToFit(450), 150);
      })
      .catch((err) => {
        if (!mounted) {
          return;
        }
        setError(err?.message || 'Failed to load state');
      })
      .finally(() => {
        if (mounted) {
          setLoading(false);
        }
      });

    return () => {
      mounted = false;
    };
  }, [initialState, token]);

  const filteredGraph = useMemo(() => {
    const query = filter.trim().toLowerCase();
    if (!query) {
      return data;
    }

    const nodes = data.nodes.filter(
      (node) =>
        (node.name || '').toLowerCase().includes(query) ||
        (node.type || '').toLowerCase().includes(query),
    );
    const allowed = new Set(nodes.map((node) => node.id));
    const links = data.links.filter(
      (link) => allowed.has(toNodeId(link.source)) && allowed.has(toNodeId(link.target)),
    );
    return { nodes, links };
  }, [data, filter]);

  const statePayload = initialState || null;
  const trustEntries = Object.entries(statePayload?.trust || {});
  const triuneAnalyses = ensureArray(statePayload?.triune_analyses);
  const actions = ensureArray(statePayload?.actions);
  const hypotheses = ensureArray(statePayload?.hypotheses);
  const relationCounts = useMemo(() => summarizeRelationCounts(data.links), [data.links]);

  return (
    <div
      className="graph-world-page"
      style={{
        height: '100%',
        padding: embedded ? 0 : 16,
        display: 'flex',
        flexWrap: embedded ? 'nowrap' : 'wrap',
        alignItems: 'flex-start',
        gap: 14,
        background: embedded
          ? 'transparent'
          : 'radial-gradient(circle at 30% 20%, rgba(0,240,255,0.08), transparent 40%), radial-gradient(circle at 75% 70%, rgba(188,19,254,0.08), transparent 45%), linear-gradient(180deg, #07101c, #02050d)',
      }}
    >
      <div style={{ flex: '1 1 680px', minWidth: 0 }}>
        <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="seraph-pip" />
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, letterSpacing: '0.32em', color: 'var(--neon-cyan)', textTransform: 'uppercase', textShadow: '0 0 8px rgba(0,240,255,0.5)' }}>
                METATRON · GRAPH
              </span>
            </div>
            <h1
              className="seraph-gradient-text"
              style={{
                fontFamily: "'Orbitron', sans-serif",
                fontWeight: 900,
                fontSize: embedded ? '1.6rem' : '2.2rem',
                letterSpacing: '0.06em',
                textTransform: 'uppercase',
                lineHeight: 1,
                margin: 0,
              }}
            >
              World Graph
            </h1>
            <p className="text-xs mt-1" style={{ color: '#9ed3e6', fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.04em' }}>
              &gt; live entity / relationship topology · {filteredGraph.nodes.length} nodes · {filteredGraph.links.length} edges
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => {
                fgRef.current && fgRef.current.zoomToFit(450);
              }}
              className="seraph-btn"
              style={{ borderRadius: 0, padding: '6px 14px', fontSize: 11 }}
            >
              FIT
            </button>
            <button
              type="button"
              onClick={() => {
                navigator.clipboard?.writeText(JSON.stringify(data));
              }}
              className="seraph-btn"
              style={{ borderRadius: 0, padding: '6px 14px', fontSize: 11 }}
            >
              EXPORT JSON
            </button>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8, marginBottom: 10, alignItems: 'center' }}>
          <input
            aria-label="filter"
            placeholder="filter by name or type…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="seraph-input"
            style={{ flex: 1, padding: '8px 12px', fontSize: 12 }}
          />
        </div>

        {loading ? (
          <div
            className="animate-pulse p-6"
            style={{
              background: 'linear-gradient(90deg, rgba(0,240,255,0.05), rgba(188,19,254,0.03))',
              border: '1px solid rgba(0,240,255,0.18)',
              color: '#aef0ff',
              fontFamily: "'JetBrains Mono', monospace",
              letterSpacing: '0.1em',
            }}
          >
            &gt; loading world state…
          </div>
        ) : null}
        {error ? <div style={{ color: '#ff8a96', fontFamily: "'JetBrains Mono', monospace" }}>error: {error}</div> : null}

        {!loading && !error ? (
          <div
            className="seraph-corner-brackets relative"
            style={{
              height: embedded ? '64vh' : '72vh',
              overflow: 'hidden',
              border: '1px solid rgba(0,240,255,0.32)',
              boxShadow: '0 0 30px rgba(0,240,255,0.18), inset 0 0 24px rgba(0,240,255,0.05)',
              background: 'radial-gradient(ellipse at center, rgba(0,240,255,0.05), transparent 60%), #02050d',
            }}
          >
            <span className="seraph-corner-tl" />
            <span className="seraph-corner-tr" />
            <span className="seraph-corner-bl" />
            <span className="seraph-corner-br" />

            {/* Subtle scanline overlay on the graph */}
            <div
              aria-hidden="true"
              style={{
                position: 'absolute',
                inset: 0,
                pointerEvents: 'none',
                zIndex: 2,
                background:
                  'repeating-linear-gradient(0deg, rgba(0,240,255,0.04) 0px, rgba(0,240,255,0.04) 1px, transparent 1px, transparent 4px)',
                mixBlendMode: 'overlay',
              }}
            />

            <ForceGraph2D
              ref={(el) => {
                fgRef.current = el;
                if (el && el.d3Force) {
                  // Push nodes apart and stretch links so the graph reads
                  el.d3Force('charge')?.strength(-260).distanceMax(620);
                  el.d3Force('link')?.distance((l) => 90 + ((l.value || 1) * 8));
                  el.d3Force('center')?.strength(0.04);
                }
              }}
              graphData={filteredGraph}
              onNodeDragEnd={(node) => {
                node.fx = node.x;
                node.fy = node.y;
              }}
              backgroundColor="rgba(0,0,0,0)"
              nodeLabel={(node) => `${node.name} (${node.type})`}
              nodeColor={(node) => node.color || '#00f0ff'}
              nodeRelSize={6}
              cooldownTicks={140}
              warmupTicks={80}
              d3AlphaDecay={0.018}
              d3VelocityDecay={0.28}
              onEngineStop={() => {
                if (fgRef.current) fgRef.current.zoomToFit(450, 60);
              }}
              linkColor={(link) => {
                const v = Number(link.value) || 1;
                if (v >= 5) return 'rgba(255,43,214,0.7)';
                if (v >= 3) return 'rgba(188,19,254,0.6)';
                return 'rgba(0,240,255,0.5)';
              }}
              linkWidth={(link) => 0.8 + Math.min(3, (link.value || 1) * 0.4)}
              linkDirectionalParticles={2}
              linkDirectionalParticleWidth={(link) => 1.4 + Math.min(2, (link.value || 1) * 0.4)}
              linkDirectionalParticleSpeed={(link) => 0.006 + (link.value || 1) * 0.014}
              linkDirectionalParticleColor={(link) =>
                (Number(link.value) || 1) >= 4 ? '#ff2bd6' : '#00f0ff'
              }
              onNodeClick={(node) => {
                setSelected(node);
                if (fgRef.current) {
                  fgRef.current.centerAt(node.x, node.y, 600);
                  fgRef.current.zoom(2.4, 600);
                }
              }}
              nodeCanvasObject={(node, ctx, globalScale) => {
                const label = node.name;
                const fontSize = Math.max(9, 13 / globalScale);
                const isSelected = selected && selected.id === node.id;
                const radius = node.type === 'host' ? 10 : node.type === 'campaign' ? 12 : 8;
                const fillColor = node.color || '#00f0ff';

                // Outer halo (radial gradient via shadowBlur)
                ctx.save();
                ctx.shadowColor = fillColor;
                ctx.shadowBlur = isSelected ? 28 : 14;
                ctx.beginPath();
                ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI);
                ctx.fillStyle = fillColor;
                ctx.fill();
                ctx.restore();

                // Inner bright core
                ctx.beginPath();
                ctx.arc(node.x, node.y, radius * 0.45, 0, 2 * Math.PI);
                ctx.fillStyle = 'rgba(255,255,255,0.9)';
                ctx.fill();

                // Selection ring
                if (isSelected) {
                  ctx.beginPath();
                  ctx.arc(node.x, node.y, radius + 4, 0, 2 * Math.PI);
                  ctx.strokeStyle = '#ffffff';
                  ctx.lineWidth = 1.5;
                  ctx.stroke();

                  ctx.beginPath();
                  ctx.arc(node.x, node.y, radius + 9, 0, 2 * Math.PI);
                  ctx.strokeStyle = fillColor;
                  ctx.lineWidth = 1;
                  ctx.setLineDash([3, 3]);
                  ctx.stroke();
                  ctx.setLineDash([]);
                }

                // Offline overlay
                if (node.status === 'offline') {
                  ctx.beginPath();
                  ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI);
                  ctx.fillStyle = 'rgba(0,0,0,0.55)';
                  ctx.fill();
                }

                // Label
                ctx.font = `bold ${fontSize}px 'JetBrains Mono', monospace`;
                ctx.fillStyle = '#e6fbff';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'top';
                ctx.shadowColor = fillColor;
                ctx.shadowBlur = 4;
                ctx.fillText(label, node.x, node.y + radius + 4);
                ctx.shadowBlur = 0;
              }}
            />
          </div>
        ) : null}
        {!loading && !error && filteredGraph.nodes.length === 0 ? (
          <div
            className="mt-3 p-4"
            style={{
              border: '1px solid rgba(0,240,255,0.22)',
              background: 'linear-gradient(160deg, rgba(9,18,38,0.86), rgba(2,8,19,0.92))',
              color: '#9ed3e6',
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 12,
              letterSpacing: '0.04em',
            }}
          >
            &gt; no world graph entities yet — nodes and attack paths populate as telemetry arrives.
          </div>
        ) : null}
      </div>

      <aside style={{ flex: '1 1 280px', width: 'min(320px, 100%)', minWidth: 260, maxWidth: 320, paddingLeft: 4 }}>
        <div
          className="seraph-corner-brackets relative p-4"
          style={{
            background: 'linear-gradient(160deg, rgba(9,18,38,0.86), rgba(2,8,19,0.92))',
            border: '1px solid rgba(0,240,255,0.32)',
            boxShadow: 'inset 0 0 18px rgba(0,240,255,0.05), 0 0 18px rgba(0,240,255,0.08)',
          }}
        >
          <span className="seraph-corner-tl" />
          <span className="seraph-corner-tr" />
          <span className="seraph-corner-bl" />
          <span className="seraph-corner-br" />

          <h3
            style={{
              fontFamily: "'Orbitron', monospace",
              fontWeight: 700,
              fontSize: '0.95rem',
              letterSpacing: '0.18em',
              textTransform: 'uppercase',
              color: '#e6fbff',
              margin: 0,
              textShadow: '0 0 10px rgba(0,240,255,0.4)',
            }}
          >
            Node · Inspector
          </h3>
          {!selected ? (
            <div
              className="mt-3"
              style={{ color: '#6aa8bc', fontSize: 12, fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.04em' }}
            >
              &gt; click a node to inspect
            </div>
          ) : null}
          {selected ? (
            <div className="mt-3" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11.5 }}>
              <div
                style={{
                  fontFamily: "'Orbitron', monospace",
                  fontSize: '1.05rem',
                  fontWeight: 700,
                  color: selected.color,
                  textShadow: `0 0 10px ${selected.color}99`,
                  marginBottom: 8,
                }}
              >
                {selected.name}
              </div>
              <div style={{ color: '#9ed3e6', display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '4px 12px' }}>
                <span style={{ color: 'var(--neon-cyan)' }}>ID</span><span style={{ color: '#e6fbff' }}>{selected.id}</span>
                <span style={{ color: 'var(--neon-cyan)' }}>TYPE</span><span style={{ color: '#e6fbff' }}>{selected.type}</span>
                <span style={{ color: 'var(--neon-cyan)' }}>RISK</span>
                <span style={{ color: selected.riskScore >= 65 ? '#ff8a96' : selected.riskScore >= 40 ? '#ffd47a' : '#7fffa6' }}>
                  {selected.riskScore ?? 0}
                </span>
              </div>
              <div className="mt-3" style={{ color: 'var(--neon-cyan)', letterSpacing: '0.16em' }}>CONNECTED</div>
              <ul style={{ maxHeight: 220, overflow: 'auto', marginTop: 4, color: '#aef0ff' }}>
                {data.links
                  .filter((link) => toNodeId(link.source) === selected.id)
                  .map((link, idx) => (
                    <li key={idx} style={{ padding: '2px 0' }}>
                      → {String(toNodeId(link.target))} <span style={{ color: '#6aa8bc' }}>v:{link.value}</span>
                    </li>
                  ))}
                {data.links
                  .filter((link) => toNodeId(link.target) === selected.id)
                  .map((link, idx) => (
                    <li key={`t-${idx}`} style={{ padding: '2px 0' }}>
                      ← {String(toNodeId(link.source))} <span style={{ color: '#6aa8bc' }}>v:{link.value}</span>
                    </li>
                  ))}
              </ul>
            </div>
          ) : null}

          <div className="mt-4 pt-3" style={{ borderTop: '1px solid rgba(0,240,255,0.18)' }}>
            <h4
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 10,
                letterSpacing: '0.32em',
                color: 'var(--neon-cyan)',
                textTransform: 'uppercase',
                marginBottom: 8,
                textShadow: '0 0 6px rgba(0,240,255,0.4)',
              }}
            >
              World Bind
            </h4>
            <div style={{ display: 'grid', gap: 6, fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }}>
              <div style={{ color: '#9ed3e6' }}>
                hash: <span style={{ color: '#e6fbff' }}>{statePayload?.world_state_hash ? `${String(statePayload.world_state_hash).slice(0, 18)}...` : 'unavailable'}</span>
              </div>
              <div style={{ color: '#9ed3e6' }}>
                triune analyses: <span style={{ color: '#e6fbff' }}>{triuneAnalyses.length}</span>
              </div>
              <div style={{ color: '#9ed3e6' }}>
                recommended actions: <span style={{ color: '#e6fbff' }}>{actions.length}</span>
              </div>
              <div style={{ color: '#9ed3e6' }}>
                hypotheses: <span style={{ color: '#e6fbff' }}>{hypotheses.length}</span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3" style={{ borderTop: '1px solid rgba(0,240,255,0.18)' }}>
            <h4
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 10,
                letterSpacing: '0.32em',
                color: 'var(--neon-cyan)',
                textTransform: 'uppercase',
                marginBottom: 8,
                textShadow: '0 0 6px rgba(0,240,255,0.4)',
              }}
            >
              Trust
            </h4>
            {trustEntries.length ? (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {trustEntries.map(([key, value]) => (
                  <span
                    key={key}
                    style={{
                      padding: '3px 8px',
                      border: '1px solid rgba(0,240,255,0.22)',
                      background: 'rgba(0,240,255,0.05)',
                      color: '#aef0ff',
                      fontSize: 10,
                    }}
                  >
                    {key}: {String(value)}
                  </span>
                ))}
              </div>
            ) : (
              <div style={{ color: '#6aa8bc', fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}>
                no trust dimensions published
              </div>
            )}
          </div>

          <div className="mt-4 pt-3" style={{ borderTop: '1px solid rgba(0,240,255,0.18)' }}>
            <h4
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 10,
                letterSpacing: '0.32em',
                color: 'var(--neon-cyan)',
                textTransform: 'uppercase',
                marginBottom: 8,
                textShadow: '0 0 6px rgba(0,240,255,0.4)',
              }}
            >
              Graph Modes
            </h4>
            <div style={{ display: 'grid', gap: 6, color: '#9ed3e6', fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}>
              {relationCounts.length ? relationCounts.map(([relation, count]) => (
                <div key={relation} style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
                  <span>{relation.replaceAll('_', ' ')}</span>
                  <span style={{ color: '#e6fbff' }}>{count}</span>
                </div>
              )) : (
                <span>relationship summary unavailable</span>
              )}
            </div>
          </div>

          <div className="mt-4 pt-3" style={{ borderTop: '1px solid rgba(0,240,255,0.18)' }}>
            <h4
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 10,
                letterSpacing: '0.32em',
                color: 'var(--neon-cyan)',
                textTransform: 'uppercase',
                marginBottom: 8,
                textShadow: '0 0 6px rgba(0,240,255,0.4)',
              }}
            >
              Legend
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {[
                { color: '#00f0ff', label: 'Host / Endpoint' },
                { color: '#bc13fe', label: 'User / Identity' },
                { color: '#ff2bd6', label: 'Campaign' },
                { color: '#7c3aed', label: 'Process' },
                { color: '#39ff14', label: 'Other Entity' },
                { color: '#ffb020', label: 'Risk ≥ 40' },
                { color: '#ff8a3c', label: 'Suspicious (≥ 65)' },
                { color: '#ff3838', label: 'Critical (≥ 85)' },
              ].map(({ color, label }) => (
                <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span
                    style={{
                      width: 10,
                      height: 10,
                      background: color,
                      display: 'inline-block',
                      borderRadius: '50%',
                      boxShadow: `0 0 6px ${color}, 0 0 14px ${color}aa`,
                    }}
                  />
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#9ed3e6', letterSpacing: '0.04em' }}>
                    {label}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </aside>
    </div>
  );
}
