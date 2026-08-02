import { useSearchParams } from 'react-router-dom';
import { Database, GitBranch, Route, Plug } from 'lucide-react';
import ThreatIntelPage from './ThreatIntelPage';
import CorrelationPage from './CorrelationPage';
import AttackPathsPage from './AttackPathsPage';
import IntegrationDiagnosticsPage from './IntegrationDiagnosticsPage';
import WorkspaceErrorBoundary from '../components/WorkspaceErrorBoundary';
import SeraphPageHeader from '../components/SeraphPageHeader';

const INVESTIGATION_ACCENTS = {
  intel: '#66e6ff',
  integrations: '#8dffb3',
  correlation: '#ffd166',
  paths: '#ff8aa8',
};

const investigationPanelStyle = (accent) => ({
  background: 'linear-gradient(160deg, rgba(8,18,34,0.92), rgba(3,9,18,0.96))',
  border: `1px solid ${accent}`,
  boxShadow: `0 0 14px ${accent}22, inset 0 0 8px rgba(255,255,255,0.02)`,
  borderRadius: '14px',
});

const investigationTabStyle = (selected, accent) => ({
  background: selected
    ? `linear-gradient(135deg, ${accent}20, rgba(255,255,255,0.03))`
    : 'linear-gradient(135deg, rgba(8,20,38,0.82), rgba(4,11,22,0.9))',
  border: `1px solid ${selected ? `${accent}55` : 'rgba(115,163,185,0.16)'}`,
  color: selected ? '#f7fbff' : '#a7c7d6',
  boxShadow: selected ? `0 0 10px ${accent}18` : 'none',
  textTransform: 'uppercase',
  letterSpacing: '0.14em',
  fontFamily: "'FfMoon', 'Orbitron', sans-serif",
});

const INVESTIGATION_TABS = [
  {
    key: 'intel',
    label: 'Threat Intel',
    description: 'Indicator lookup, feed health, and external integrations.',
    icon: Database,
    render: () => <ThreatIntelPage />,
  },
  {
    key: 'integrations',
    label: 'Integrations',
    description: 'Run integration diagnostics (containers/scripts) and inspect job status.',
    icon: Plug,
    render: () => (
      <IntegrationDiagnosticsPage
        allowedTools={[
          'amass',
          'arkime',
          'spiderfoot',
          'purplesharp',
          'bloodhound',
          'velociraptor',
          'yara',
          'zeek',
          'clamav',
        ]}
        defaultTool="amass"
        title="Investigation Integrations"
        description="On-demand investigative tools. Start only what you need and keep the rest idle."
      />
    ),
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
    <div className="p-6 space-y-6" data-testid="investigation-page" data-accent="cyan">
      <SeraphPageHeader
        eyebrow="seraph · investigation · signal correlation"
        title="Investigation Workspace"
        tagline="> unified investigation flow across intelligence, correlation, and attack path analysis"
        accent="cyan"
        status={activeConfig.label.toUpperCase()}
      />

      <div className="seraph-content-panel" style={{ ...investigationPanelStyle(INVESTIGATION_ACCENTS[activeTab] || INVESTIGATION_ACCENTS.intel), padding: '0.7rem' }}>
        <div className="flex flex-wrap gap-2">
          {INVESTIGATION_TABS.map((tab) => {
            const selected = tab.key === activeTab;
            const Icon = tab.icon;
            const accent = INVESTIGATION_ACCENTS[tab.key] || INVESTIGATION_ACCENTS.intel;
            return (
              <button
                key={tab.key}
                type="button"
                onClick={() => setTab(tab.key)}
                className="flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-colors"
                style={investigationTabStyle(selected, accent)}
              >
                <Icon className="w-4 h-4" style={{ color: selected ? accent : '#89b7c9' }} />
                {tab.label}
              </button>
            );
          })}
        </div>
        <p className="sophia-terminal-meta text-xs mt-3 px-1">{activeConfig.description}</p>
      </div>

      <WorkspaceErrorBoundary title={`${activeConfig.label} pane failed`}>
        <div className="seraph-nested-workspace">{activeConfig.render()}</div>
      </WorkspaceErrorBoundary>
    </div>
  );
}
