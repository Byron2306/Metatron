import React, {useEffect, useState, useRef} from 'react'
import axios from 'axios'
import ForceGraph2D from 'react-force-graph-2d'

type RawEntity = any

export default function GraphWorld(): JSX.Element {
  const [data, setData] = useState<{nodes: any[]; links: any[]}>({nodes: [], links: []})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<any | null>(null)
  const [filter, setFilter] = useState<string>('')
  const fgRef = useRef<any>()

  useEffect(() => {
    let mounted = true
    setLoading(true)
    axios.get('/api/metatron/state')
      .then(res => {
        if (!mounted) return
        const state = res.data || {}
        const ents: RawEntity[] = state.entities || []
        const rels: any[] = state.relationships || []
        const nodes = ents.map((e: any, i: number) => ({ id: e.id || e._id || `ent:${i}`, name: e.name || e.type || e.id || `node-${i}`, type: e.type || 'entity' }))
        const links = rels.map((r: any) => ({ source: r.source, target: r.target, value: r.score || 1 }))
        setData({nodes, links})
        // center graph after nodes loaded
        setTimeout(() => fgRef.current && fgRef.current.zoomToFit(400), 200)
      })
      .catch(e => setError(e?.message || 'Failed to load state'))
      .finally(() => mounted && setLoading(false))
    return () => { mounted = false }
  }, [])

  return (
    <div className="graph-world-page" style={{height: '100%', padding: 12, display:'flex', gap:12}}>
      <div style={{flex:1}}>
        <h1 style={{marginBottom:8}}>World Graph</h1>
        <div style={{display:'flex', gap:8, marginBottom:8, alignItems:'center'}}>
          <input aria-label="filter" placeholder="Filter by name or type" value={filter} onChange={e => setFilter(e.target.value)} style={{flex:1, padding:6, borderRadius:6, border:'1px solid #ccc'}} />
          <button onClick={() => { fgRef.current && fgRef.current.zoomToFit(400) }} style={{padding:'6px 10px'}}>Fit</button>
        </div>
        {loading && <div>Loading world state…</div>}
        {error && <div style={{color:'darkred'}}>Error: {error}</div>}
        {!loading && !error && (
          <div style={{height: '70vh', border: '1px solid #e6e6e6'}}>
            <ForceGraph2D
              ref={fgRef}
              graphData={filter ? { nodes: data.nodes.filter(n => (n.name||'').toLowerCase().includes(filter.toLowerCase()) || (n.type||'').toLowerCase().includes(filter.toLowerCase())), links: data.links.filter(l => {
                // keep links where both ends survive filter
                const src = data.nodes.find(n=>n.id===l.source)
                const tgt = data.nodes.find(n=>n.id===l.target)
                const keep = (src && ((src.name||'').toLowerCase().includes(filter.toLowerCase()) || (src.type||'').toLowerCase().includes(filter.toLowerCase()))) && (tgt && ((tgt.name||'').toLowerCase().includes(filter.toLowerCase()) || (tgt.type||'').toLowerCase().includes(filter.toLowerCase())))
                return keep
              }) } : data }
              nodeLabel={(n: any) => `${n.name} (${n.type})`}
              nodeAutoColorBy={'type'}
              linkDirectionalParticles={1}
              linkDirectionalParticleSpeed={(d:any) => 0.01 + (d.value||1)*0.02}
              onNodeClick={(node:any) => { setSelected(node) }}
              nodeCanvasObject={(node:any, ctx:any, globalScale:any) => {
                const label = node.name
                const fontSize = 12/globalScale
                ctx.font = `${fontSize}px Sans-Serif`
                const textWidth = ctx.measureText(label).width
                const bckgDimensions = [textWidth + 8, fontSize + 4]
                ctx.fillStyle = selected && selected.id === node.id ? 'rgba(30,144,255,0.9)' : 'rgba(0,0,0,0.6)'
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
      <aside style={{width:320, borderLeft:'1px solid #e6e6e6', paddingLeft:12}}>
        <h2 style={{marginTop:6}}>Details</h2>
        {!selected && <div style={{color:'#666'}}>Click a node to see details</div>}
        {selected && (
          <div>
            <h3 style={{marginBottom:4}}>{selected.name}</h3>
            <div><strong>ID:</strong> {selected.id}</div>
            <div><strong>Type:</strong> {selected.type}</div>
            <div style={{marginTop:8}}><strong>Connected to:</strong></div>
            <ul style={{maxHeight:200, overflow:'auto'}}>
              {data.links.filter((l:any)=>l.source===selected.id).map((l:any,i)=> <li key={i}>{String(l.target)} (v:{l.value})</li>)}
              {data.links.filter((l:any)=>l.target===selected.id).map((l:any,i)=> <li key={`t-${i}`}>{String(l.source)} (v:{l.value})</li>)}
            </ul>
            <div style={{marginTop:8}}>
              <button onClick={() => { navigator.clipboard?.writeText(JSON.stringify(selected)); }} style={{padding:6}}>Copy JSON</button>
            </div>
          </div>
        )}
        <div style={{marginTop:20}}>
          <h4>Legend</h4>
          <div style={{display:'flex',gap:8,alignItems:'center'}}><span style={{width:12,height:12,background:'#999',display:'inline-block'}}/> <span style={{color:'#666'}}>Node</span></div>
        </div>
      </aside>
    </div>
  )
}
