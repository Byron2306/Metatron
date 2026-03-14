import React, { useEffect, useState, useRef } from 'react'
import axios from 'axios'
import ForceGraph2D from 'react-force-graph-2d'

export const triuneRoles = ['Metatron','Michael','Loki']

export default function GraphWorld() {
  const [data, setData] = useState({ nodes: [], links: [] })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(null)
  const [filter, setFilter] = useState('')
  const fgRef = useRef(null)

  useEffect(() => {
    let mounted = true
    setLoading(true)
    axios.get('/api/metatron/state')
      .then(res => {
        if (!mounted) return
        const state = res.data || {}
        const ents = state.entities || []
        const rels = state.relationships || []
        const nodes = ents.map((e, i) => ({ id: e.id || e._id || `ent:${i}`, name: e.name || e.type || e.id || `node-${i}`, type: e.type || 'entity' }))
        const links = rels.map(r => ({ source: r.source, target: r.target, value: r.score || 1 }))
        setData({ nodes, links })
        setTimeout(() => fgRef.current && fgRef.current.zoomToFit(400), 200)
      })
      .catch(e => setError(e?.message || 'Failed to load state'))
      .finally(() => mounted && setLoading(false))
    return () => { mounted = false }
  }, [])

  return (
    <div className="graph-world-page" style={{height: '100%', padding: 12, display:'flex', gap:12, background: 'linear-gradient(180deg,#071027, #071021)'}}>
      <div style={{flex:1}}>
        <div className="flex items-center justify-between mb-3">
          <div>
            <h1 className="text-2xl font-bold" style={{color:'#E6F6F7'}}>World Graph</h1>
            <p className="text-sm text-slate-400">Interactive map of entities and relationships</p>
          </div>
          <div style={{display:'flex',gap:8}}>
            <button onClick={() => { fgRef.current && fgRef.current.zoomToFit(400) }} className="px-3 py-2 rounded-md" style={{background:'#0ea5a4',color:'#042A2B'}}>Fit</button>
            <button onClick={() => { navigator.clipboard?.writeText(JSON.stringify(data)); }} className="px-3 py-2 rounded-md" style={{background:'#06b6d4',color:'#042A2B'}}>Export JSON</button>
          </div>
        </div>

        <div style={{display:'flex', gap:8, marginBottom:8, alignItems:'center'}}>
          <input aria-label="filter" placeholder="Filter by name or type" value={filter} onChange={e => setFilter(e.target.value)} style={{flex:1, padding:8, borderRadius:8, border:'1px solid rgba(255,255,255,0.06)', background:'rgba(255,255,255,0.02)', color:'#E6F6F7'}} />
        </div>

        {loading && <div className="animate-pulse p-6 rounded-md" style={{background:'linear-gradient(90deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01))'}}>Loading world state…</div>}
        {error && <div style={{color:'salmon'}}>Error: {error}</div>}
        {!loading && !error && (
          <div style={{height: '72vh', borderRadius:12, overflow:'hidden', boxShadow:'0 10px 30px rgba(2,6,23,0.6)'}}>
            <ForceGraph2D
              ref={fgRef}
              graphData={filter ? { nodes: data.nodes.filter(n => (n.name||'').toLowerCase().includes(filter.toLowerCase()) || (n.type||'').toLowerCase().includes(filter.toLowerCase())), links: data.links.filter(l => {
                const src = data.nodes.find(n=>n.id===l.source)
                const tgt = data.nodes.find(n=>n.id===l.target)
                const keep = (src && ((src.name||'').toLowerCase().includes(filter.toLowerCase()) || (src.type||'').toLowerCase().includes(filter.toLowerCase()))) && (tgt && ((tgt.name||'').toLowerCase().includes(filter.toLowerCase()) || (tgt.type||'').toLowerCase().includes(filter.toLowerCase())))
                return keep
              }) } : data }
              nodeLabel={n => `${n.name} (${n.type})`}
              nodeAutoColorBy={'type'}
              linkDirectionalParticles={1}
              linkDirectionalParticleSpeed={d => 0.01 + (d.value||1)*0.02}
              onNodeClick={node => { setSelected(node) }}
              nodeCanvasObject={(node, ctx, globalScale) => {
                const label = node.name
                const fontSize = Math.max(10, 14/globalScale)
                ctx.font = `${fontSize}px Sans-Serif`
                const textWidth = ctx.measureText(label).width
                const bckgDimensions = [textWidth + 10, fontSize + 6]
                ctx.fillStyle = selected && selected.id === node.id ? 'rgba(14,165,164,0.95)' : 'rgba(10,10,12,0.6)'
                ctx.fillRect(node.x - bckgDimensions[0]/2, node.y - bckgDimensions[1]/2, ...bckgDimensions)
                ctx.fillStyle = '#fff'
                ctx.textAlign = 'center'
                ctx.textBaseline = 'middle'
                ctx.fillText(label, node.x, node.y)
              }}
            />
          </div>
        )}
      </div>

      <aside style={{width:340, paddingLeft:16}}>
        <div className="p-4 rounded-lg" style={{background:'linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01))', border:'1px solid rgba(255,255,255,0.03)'}}>
          <h3 className="font-semibold text-white">Details</h3>
          {!selected && <div className="text-slate-400 mt-2">Click a node to see details</div>}
          {selected && (
            <div className="mt-3 text-sm text-slate-200">
              <div className="text-lg font-bold">{selected.name}</div>
              <div className="mt-2"><strong>ID:</strong> {selected.id}</div>
              <div><strong>Type:</strong> {selected.type}</div>
              <div style={{marginTop:8}}><strong>Connected to:</strong></div>
              <ul style={{maxHeight:200, overflow:'auto'}}>
                {data.links.filter(l=>l.source===selected.id).map((l,i)=> <li key={i}>{String(l.target)} (v:{l.value})</li>)}
                {data.links.filter(l=>l.target===selected.id).map((l,i)=> <li key={`t-${i}`}>{String(l.source)} (v:{l.value})</li>)}
              </ul>
            </div>
          )}

          <div className="mt-4">
            <h4 className="text-sm text-slate-300">Legend</h4>
            <div className="mt-2" style={{display:'flex',flexDirection:'column',gap:6}}>
              <div style={{display:'flex',alignItems:'center',gap:8}}><span style={{width:14,height:14,background:'#999',display:'inline-block',borderRadius:4}}/> <span className="text-slate-400">Generic Node</span></div>
              <div style={{display:'flex',alignItems:'center',gap:8}}><span style={{width:14,height:14,background:'#0ea5a4',display:'inline-block',borderRadius:4}}/> <span className="text-slate-400">High‑value</span></div>
              <div style={{display:'flex',alignItems:'center',gap:8}}><span style={{width:14,height:14,background:'#f97316',display:'inline-block',borderRadius:4}}/> <span className="text-slate-400">Suspicious</span></div>
            </div>
          </div>
        </div>
      </aside>
    </div>
  )
}
