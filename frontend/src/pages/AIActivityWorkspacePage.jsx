import { useSearchParams } from 'react-router-dom';
import { useEffect, useState } from 'react';
import { Brain, Terminal, Radar, Database, Gauge, Shield } from 'lucide-react';
import AIDetectionPage from './AIDetectionPage';
import AIThreatIntelligence from './AIThreatIntelligence';
import CLISessionsPage from './CLISessionsPage';
import WorkspaceErrorBoundary from '../components/WorkspaceErrorBoundary';
import SeraphPageHeader from '../components/SeraphPageHeader';

const hexToRgb = (hex) => {
  const cleanHex = hex.replace('#', '');
  const bigint = parseInt(cleanHex, 16);
  const r = (bigint >> 16) & 255;
  const g = (bigint >> 8) & 255;
  const b = bigint & 255;
  return `${r}, ${g}, ${b}`;
};

const AI_ACTIVITY_ACCENTS = {
  signals: '#10B981',
  intelligence: '#F59E0B',
  sessions: '#06B6D4',
};

const aiWorkspacePanelStyle = (accent) => {
  const rgb = hexToRgb(accent);
  return {
    background: 'linear-gradient(160deg, rgba(8,18,34,0.92), rgba(3,9,18,0.96))',
    border: `1px solid ${accent}`,
    boxShadow: `0 0 14px ${accent}33, inset 0 0 8px rgba(255,255,255,0.02)`,
    borderRadius: '14px',
  };
};

const aiWorkspaceTabStyle = (selected, accent) => {
  const rgb = hexToRgb(accent);
  return {
    background: selected ? `linear-gradient(135deg, rgba(${rgb},0.12), rgba(255,255,255,0.03))` : 'linear-gradient(135deg, rgba(8,20,38,0.82), rgba(4,11,22,0.9))',
    border: `1px solid ${selected ? `${accent}55` : 'rgba(115,163,185,0.16)'}`,
    color: selected ? '#f7fbff' : '#a7c7d6',
    boxShadow: selected ? `0 0 10px rgba(${rgb},0.18)` : 'none',
    textTransform: 'uppercase',
    letterSpacing: '0.14em',
    fontFamily: "'FfMoon', 'Orbitron', sans-serif",
  };
};

const AI_ACTIVITY_TABS = [
  {
    key: 'signals',
    label: 'Live Signals',
    description: 'Interactive AI analysis and detection runs.',
    icon: Radar,
    render: () => <AIDetectionPage />,
  },
  {
    key: 'intelligence',
    label: 'Threat Intelligence',
    description: 'AATL/AATR threat landscape and indicators.',
    icon: Brain,
    render: () => <AIThreatIntelligence />,
  },
  {
    key: 'sessions',
    label: 'Session Intelligence',
    description: 'CLI session behavior and machine-likelihood telemetry.',
    icon: Terminal,
    render: () => <CLISessionsPage />,
  },
];

const DEFAULT_TAB = 'signals';

const formatPercent = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return '0%';
  return `${(numeric * 100).toFixed(0)}%`;
};

export default function AIActivityWorkspacePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [aabSnapshot, setAabSnapshot] = useState(null);
  const rawTab = (searchParams.get('tab') || DEFAULT_TAB).toLowerCase();
  const activeTab = AI_ACTIVITY_TABS.some((tab) => tab.key === rawTab) ? rawTab : DEFAULT_TAB;
  const activeConfig = AI_ACTIVITY_TABS.find((tab) => tab.key === activeTab) || AI_ACTIVITY_TABS[0];

  const setTab = (nextTab) => {
    const next = new URLSearchParams(searchParams);
    if (nextTab === DEFAULT_TAB) {
      next.delete('tab');
    } else {
      next.set('tab', nextTab);
    }
    setSearchParams(next, { replace: true });
  };

  useEffect(() => {
    let cancelled = false;
    fetch('/aab-live-latest.json', { cache: 'no-store' })
      .then((response) => (response.ok ? response.json() : null))
      .then((payload) => {
        if (!cancelled) setAabSnapshot(payload);
      })
      .catch(() => {
        if (!cancelled) setAabSnapshot(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="p-6 space-y-6" data-accent="cyan">
      <SeraphPageHeader
        eyebrow="seraph · ai-activity · cognition telemetry"
        title="AI Activity Workspace"
        tagline="> unified surface for AI detection, intelligence, and session-level behavioral analysis"
        accent="cyan"
        status={activeConfig.label.toUpperCase()}
      />

      <div style={{ ...aiWorkspacePanelStyle(AI_ACTIVITY_ACCENTS[activeTab] || AI_ACTIVITY_ACCENTS.signals), padding: '0.7rem' }}>
        <div className="flex flex-wrap gap-2">
          {AI_ACTIVITY_TABS.map((tab) => {
            const selected = tab.key === activeTab;
            const Icon = tab.icon;
            const accent = AI_ACTIVITY_ACCENTS[tab.key] || AI_ACTIVITY_ACCENTS.signals;
            return (
              <button
                key={tab.key}
                type="button"
                onClick={() => setTab(tab.key)}
                className="flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-colors"
                style={aiWorkspaceTabStyle(selected, accent)}
              >
                <Icon className="w-4 h-4" style={{ color: selected ? accent : '#a7c7d6' }} />
                {tab.label}
              </button>
            );
          })}
        </div>
        <p className="sophia-terminal-meta text-xs mt-3 px-1">{activeConfig.description}</p>
      </div>

      {aabSnapshot && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div style={{ ...aiWorkspacePanelStyle('#ffd166'), padding: '0.85rem' }}>
            <div className="flex items-center gap-2 text-slate-300 text-xs uppercase tracking-wide">
              <Database className="w-4 h-4 text-yellow-300" />
              Latest AAB Classes
            </div>
            <div className="text-2xl font-bold text-white mt-1">{aabSnapshot.run_count || 0}</div>
          </div>
          <div style={{ ...aiWorkspacePanelStyle('#7ce2a3'), padding: '0.85rem' }}>
            <div className="flex items-center gap-2 text-slate-300 text-xs uppercase tracking-wide">
              <Shield className="w-4 h-4 text-green-300" />
              Contained Runs
            </div>
            <div className="text-2xl font-bold text-white mt-1">
              {aabSnapshot.contained_count || 0} / {aabSnapshot.run_count || 0}
            </div>
          </div>
          <div style={{ ...aiWorkspacePanelStyle('#ff8ad9'), padding: '0.85rem' }}>
            <div className="flex items-center gap-2 text-slate-300 text-xs uppercase tracking-wide">
              <Gauge className="w-4 h-4 text-pink-300" />
              Avg Max Agenticity
            </div>
            <div className="text-2xl font-bold text-white mt-1">
              {formatPercent(aabSnapshot.agenticity?.avg_max_score)}
            </div>
          </div>
        </div>
      )}

      <WorkspaceErrorBoundary title={`${activeConfig.label} pane failed`}>
        <div>{activeConfig.render()}</div>
      </WorkspaceErrorBoundary>
    </div>
  );
}
