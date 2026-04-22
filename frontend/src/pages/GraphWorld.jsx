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
  if (riskScore >= 85) return '#ef4444';
  if (riskScore >= 65) return '#f97316';
  if (riskScore >= 40) return '#f59e0b';
  if (type === 'host') return '#38bdf8';
  if (type === 'user') return '#a78bfa';
  if (type === 'campaign') return '#f43f5e';
  return '#22c55e';
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

  return (
    <div
      className="graph-world-page"
      style={{
        height: '100%',
        padding: embedded ? 0 : 12,
        display: 'flex',
        gap: 12,
        background: embedded ? 'transparent' : 'linear-gradient(180deg,#071027,#071021)',
      }}
    >
      <div style={{ flex: 1 }}>
        <div className="flex items-center justify-between mb-3">
          <div>
            <h1 className={`${embedded ? 'text-xl' : 'text-2xl'} font-bold`} style={{ color: '#E6F6F7' }}>
              World Graph
            </h1>
            <p className="text-sm text-slate-400">Interactive map of entities and relationships</p>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              onClick={() => {
                fgRef.current && fgRef.current.zoomToFit(450);
              }}
              className="px-3 py-2 rounded-md"
              style={{ background: '#0ea5a4', color: '#042A2B' }}
            >
              Fit
            </button>
            <button
              onClick={() => {
                navigator.clipboard?.writeText(JSON.stringify(data));
              }}
              className="px-3 py-2 rounded-md"
              style={{ background: '#06b6d4', color: '#042A2B' }}
            >
              Export JSON
            </button>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8, marginBottom: 8, alignItems: 'center' }}>
          <input
            aria-label="filter"
            placeholder="Filter by name or type"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            style={{
              flex: 1,
              padding: 8,
              borderRadius: 8,
              border: '1px solid rgba(255,255,255,0.06)',
              background: 'rgba(255,255,255,0.02)',
              color: '#E6F6F7',
            }}
          />
        </div>

        {loading ? (
          <div
            className="animate-pulse p-6 rounded-md"
            style={{ background: 'linear-gradient(90deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01))' }}
          >
            Loading world state...
          </div>
        ) : null}
        {error ? <div style={{ color: 'salmon' }}>Error: {error}</div> : null}

        {!loading && !error ? (
          <div
            style={{
              height: embedded ? '64vh' : '72vh',
              borderRadius: 12,
              overflow: 'hidden',
              boxShadow: '0 10px 30px rgba(2,6,23,0.6)',
            }}
          >
            <ForceGraph2D
              ref={fgRef}
              graphData={filteredGraph}
              nodeLabel={(node) => `${node.name} (${node.type})`}
              nodeColor={(node) => node.color || '#38bdf8'}
              linkDirectionalParticles={1}
              linkDirectionalParticleSpeed={(link) => 0.01 + (link.value || 1) * 0.02}
              onNodeClick={(node) => {
                setSelected(node);
              }}
              nodeCanvasObject={(node, ctx, globalScale) => {
                const label = node.name;
                const fontSize = Math.max(9, 13 / globalScale);
                const isSelected = selected && selected.id === node.id;
                const radius = node.type === 'host' ? 10 : node.type === 'campaign' ? 12 : 8;
                const fillColor = isSelected ? 'rgba(14,165,164,0.95)' : (node.color || '#38bdf8');

                // Draw circle node
                ctx.beginPath();
                ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI);
                ctx.fillStyle = fillColor + 'cc';
                ctx.fill();
                ctx.strokeStyle = isSelected ? '#fff' : fillColor;
                ctx.lineWidth = isSelected ? 2 : 1;
                ctx.stroke();

                // Offline agents get a dim overlay
                if (node.status === 'offline') {
                  ctx.beginPath();
                  ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI);
                  ctx.fillStyle = 'rgba(0,0,0,0.5)';
                  ctx.fill();
                }

                // Label below node
                ctx.font = `${fontSize}px Sans-Serif`;
                ctx.fillStyle = '#e2e8f0';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'top';
                ctx.fillText(label, node.x, node.y + radius + 2);
              }}
            />
          </div>
        ) : null}
        {!loading && !error && filteredGraph.nodes.length === 0 ? (
          <div className="mt-3 p-3 rounded-md border border-slate-700 bg-slate-900/60 text-sm text-slate-300">
            No world graph entities are available yet. As telemetry arrives, nodes and attack paths will appear here automatically.
          </div>
        ) : null}
      </div>

      <aside style={{ width: 320, paddingLeft: 12 }}>
        <div
          className="p-4 rounded-lg"
          style={{
            background: 'linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01))',
            border: '1px solid rgba(255,255,255,0.03)',
          }}
        >
          <h3 className="font-semibold text-white">Details</h3>
          {!selected ? <div className="text-slate-400 mt-2">Click a node to see details</div> : null}
          {selected ? (
            <div className="mt-3 text-sm text-slate-200">
              <div className="text-lg font-bold">{selected.name}</div>
              <div className="mt-2">
                <strong>ID:</strong> {selected.id}
              </div>
              <div>
                <strong>Type:</strong> {selected.type}
              </div>
              <div>
                <strong>Risk:</strong> {selected.riskScore ?? 0}
              </div>
              <div style={{ marginTop: 8 }}>
                <strong>Connected to:</strong>
              </div>
              <ul style={{ maxHeight: 200, overflow: 'auto' }}>
                {data.links
                  .filter((link) => toNodeId(link.source) === selected.id)
                  .map((link, idx) => (
                    <li key={idx}>
                      {String(toNodeId(link.target))} (v:{link.value})
                    </li>
                  ))}
                {data.links
                  .filter((link) => toNodeId(link.target) === selected.id)
                  .map((link, idx) => (
                    <li key={`t-${idx}`}>
                      {String(toNodeId(link.source))} (v:{link.value})
                    </li>
                  ))}
              </ul>
            </div>
          ) : null}

          <div className="mt-4">
            <h4 className="text-sm text-slate-300">Legend</h4>
            <div className="mt-2" style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {[
                { color: '#38bdf8', label: 'Host / Endpoint' },
                { color: '#a78bfa', label: 'User / Identity' },
                { color: '#f43f5e', label: 'Campaign' },
                { color: '#22c55e', label: 'Other Entity' },
                { color: '#f97316', label: 'Suspicious (risk 65+)' },
                { color: '#ef4444', label: 'Critical (risk 85+)' },
              ].map(({ color, label }) => (
                <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ width: 12, height: 12, background: color, display: 'inline-block', borderRadius: '50%' }} />
                  <span className="text-slate-400 text-xs">{label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </aside>
    </div>
  );
}
