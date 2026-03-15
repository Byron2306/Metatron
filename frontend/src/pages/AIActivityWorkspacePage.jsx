import { useSearchParams } from 'react-router-dom';
import { Brain, Terminal, Radar } from 'lucide-react';
import AIDetectionPage from './AIDetectionPage';
import AIThreatIntelligence from './AIThreatIntelligence';
import CLISessionsPage from './CLISessionsPage';

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

export default function AIActivityWorkspacePage() {
  const [searchParams, setSearchParams] = useSearchParams();
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

  return (
    <div className="p-6 space-y-6">
      <div className="space-y-2">
        <h1 className="text-2xl font-bold text-white">AI Activity Workspace</h1>
        <p className="text-sm text-slate-400">
          Unified surface for AI detection, intelligence, and session-level behavioral analysis.
        </p>
      </div>

      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-2">
        <div className="flex flex-wrap gap-2">
          {AI_ACTIVITY_TABS.map((tab) => {
            const selected = tab.key === activeTab;
            const Icon = tab.icon;
            return (
              <button
                key={tab.key}
                type="button"
                onClick={() => setTab(tab.key)}
                className="flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-colors"
                style={
                  selected
                    ? { backgroundColor: 'rgba(56,189,248,0.18)', color: '#7dd3fc' }
                    : { color: '#94a3b8' }
                }
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            );
          })}
        </div>
        <p className="text-xs text-slate-500 mt-3 px-1">{activeConfig.description}</p>
      </div>

      <div>{activeConfig.render()}</div>
    </div>
  );
}
