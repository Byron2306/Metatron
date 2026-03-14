import React from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function WorldGraph() {
  const { token } = useAuth();

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">World Graph</h2>
          <p className="text-sm text-slate-400">Interactive visualization of entities and attack paths</p>
        </div>
        <div>
          <Link to="/world" className="px-3 py-2 rounded-md bg-slate-700 text-white shadow-sm">Back to World View</Link>
        </div>
      </div>

      <div className="card p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="font-semibold">Graph Overview</h3>
          <div className="text-sm text-slate-400">Live | Joined Nodes: 0</div>
        </div>

        <div className="bg-gradient-to-br from-slate-900 to-slate-800 rounded-md p-4" style={{minHeight: 480}}>
          {/* Placeholder canvas / graph area - integrate vis.js or cytoscape later */}
          <div className="w-full h-full flex items-center justify-center text-slate-500">
            <svg width="240" height="160" viewBox="0 0 240 160" fill="none" xmlns="http://www.w3.org/2000/svg">
              <rect x="0" y="0" width="240" height="160" rx="8" fill="#0f1724" />
              <circle cx="60" cy="80" r="22" fill="#06b6d4" />
              <circle cx="120" cy="40" r="18" fill="#7c3aed" />
              <circle cx="180" cy="100" r="20" fill="#0ea5a4" />
              <line x1="80" y1="80" x2="102" y2="46" stroke="#94a3b8" strokeWidth="2" strokeDasharray="4 2" />
              <line x1="138" y1="52" x2="160" y2="94" stroke="#94a3b8" strokeWidth="2" strokeDasharray="4 2" />
            </svg>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card p-4">
          <h4 className="font-semibold">Selected Node</h4>
          <p className="text-sm text-slate-400 mt-2">No node selected.</p>
        </div>
        <div className="card p-4">
          <h4 className="font-semibold">Filters</h4>
          <p className="text-sm text-slate-400 mt-2">Show: All / High Risk / Contained</p>
        </div>
        <div className="card p-4">
          <h4 className="font-semibold">Controls</h4>
          <div className="mt-3 space-x-2">
            <button className="px-3 py-2 bg-emerald-500 text-black rounded">Refresh</button>
            <button className="px-3 py-2 bg-sky-600 text-white rounded">Export</button>
          </div>
        </div>
      </div>
    </div>
  );
}
