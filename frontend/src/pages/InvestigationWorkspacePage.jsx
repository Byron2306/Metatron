import { useSearchParams } from 'react-router-dom';
import { Database, GitBranch, Route } from 'lucide-react';
import ThreatIntelPage from './ThreatIntelPage';
import CorrelationPage from './CorrelationPage';
import AttackPathsPage from './AttackPathsPage';

const INVESTIGATION_TABS = [
  {
    key: 'intel',
    label: 'Threat Intel',
    description: 'Indicator lookup, feed health, and external integrations.',
    icon: Database,
    render: () => <ThreatIntelPage />,
  },
  {
    key: 'correlation',
    label: 'Correlation',
    description: 'Cross-signal campaign correlation, attribution, and auto-actions.',
    icon: GitBranch,
    render: () => <CorrelationPage />,
  },
  {
    key: 'paths',
    label: 'Attack Paths',
    description: 'Attack graph exploration and critical path risk analysis.',
    icon: Route,
    render: () => <AttackPathsPage />,
  },
];

const DEFAULT_TAB = 'intel';

export default function InvestigationWorkspacePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const rawTab = (searchParams.get('tab') || DEFAULT_TAB).toLowerCase();
  const activeTab = INVESTIGATION_TABS.some((tab) => tab.key === rawTab) ? rawTab : DEFAULT_TAB;
  const activeConfig = INVESTIGATION_TABS.find((tab) => tab.key === activeTab) || INVESTIGATION_TABS[0];

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
        <h1 className="text-2xl font-bold text-white">Investigation Workspace</h1>
        <p className="text-sm text-slate-400">
          Unified investigation flow across intelligence, correlation, and attack path analysis.
        </p>
      </div>

      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-2">
        <div className="flex flex-wrap gap-2">
          {INVESTIGATION_TABS.map((tab) => {
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
                    ? { backgroundColor: 'rgba(139,92,246,0.2)', color: '#c4b5fd' }
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
