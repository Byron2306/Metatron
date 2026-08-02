import { useSearchParams } from 'react-router-dom';
import { Shield, FlaskConical, Radio, Terminal, Plug } from 'lucide-react';
import SigmaPage from './SigmaPage';
import MitreAttackCoveragePage from './MitreAttackCoveragePage';
import AtomicValidationPage from './AtomicValidationPage';
import OsqueryFleetPage from './OsqueryFleetPage';
import IntegrationDiagnosticsPage from './IntegrationDiagnosticsPage';
import SeraphPageHeader from '../components/SeraphPageHeader';

const DETECTION_WORKSPACE_ACCENTS = {
  sigma: '#bc13fe',
  osquery: '#39ff14',
  integrations: '#fbbf24',
  mitre: '#ff2bd6',
  atomic: '#fbbf24',
};

const detectionWorkspacePanelStyle = (accent) => ({
  background: 'linear-gradient(160deg, rgba(8,18,34,0.92), rgba(3,9,18,0.96))',
  border: `1px solid ${accent}66`,
  boxShadow: `0 0 12px ${accent}18, inset 0 0 8px rgba(255,255,255,0.02)`,
  borderRadius: '14px',
});

const detectionWorkspaceTabStyle = (selected, accent) => ({
  background: selected ? 'linear-gradient(180deg, rgba(20,18,38,0.94), rgba(7,14,26,0.96))' : 'linear-gradient(180deg, rgba(8,20,38,0.82), rgba(4,11,22,0.9))',
  border: `1px solid ${selected ? `${accent}44` : 'rgba(115,163,185,0.16)'}`,
  color: selected ? '#ffe6fb' : '#a7c7d6',
  boxShadow: selected ? `inset 0 -2px 0 ${accent}, 0 0 8px ${accent}14` : 'none',
  textTransform: 'uppercase',
  letterSpacing: '0.14em',
  fontFamily: "'FfMoon', 'Orbitron', sans-serif",
});

const DETECTION_ENGINEERING_TABS = [
  {
    key: 'sigma',
    label: 'Sigma',
    description: 'Rule logic and detection content curation.',
    icon: Shield,
    render: () => <SigmaPage />,
  },
  {
    key: 'osquery',
    label: 'Osquery',
    description: 'Fleet inventory and live query runner.',
    icon: Terminal,
    render: () => <OsqueryFleetPage />,
  },
  {
    key: 'integrations',
    label: 'Integrations',
    description: 'Detection integration runtime controls for osquery, atomic, and supporting tools.',
    icon: Plug,
    render: () => (
      <IntegrationDiagnosticsPage
        allowedTools={['osquery', 'atomic', 'yara', 'velociraptor']}
        defaultTool="osquery"
        title="Detection Integrations"
        description="Run osquery, atomic, and supporting detection integrations on demand."
      />
    ),
  },
  {
    key: 'mitre',
    label: 'MITRE ATT&CK',
    description: 'Coverage mapping and ATT&CK alignment.',
    icon: Radio,
    render: () => <MitreAttackCoveragePage />,
  },
  {
    key: 'atomic',
    label: 'Atomic Validation',
    description: 'Validation loop for detection efficacy against mapped techniques.',
    icon: FlaskConical,
    render: () => <AtomicValidationPage />,
  },
];

const DEFAULT_TAB = 'sigma';

export default function DetectionEngineeringWorkspacePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const rawTab = (searchParams.get('tab') || DEFAULT_TAB).toLowerCase();
  const activeTab = DETECTION_ENGINEERING_TABS.some((tab) => tab.key === rawTab) ? rawTab : DEFAULT_TAB;
  const activeConfig = DETECTION_ENGINEERING_TABS.find((tab) => tab.key === activeTab) || DETECTION_ENGINEERING_TABS[0];

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
      <SeraphPageHeader
        eyebrow="seraph · detection-engineering · validation loop"
        title="Detection Engineering"
        tagline="> unified engineering workspace for rule authoring, ATT&CK coverage, and atomic validation"
        accent="orange"
        status={activeConfig.label.toUpperCase()}
      />

      <div style={{ ...detectionWorkspacePanelStyle(DETECTION_WORKSPACE_ACCENTS[activeTab] || DETECTION_WORKSPACE_ACCENTS.sigma), padding: '0.7rem' }}>
        <div className="flex flex-wrap gap-2">
          {DETECTION_ENGINEERING_TABS.map((tab) => {
            const selected = tab.key === activeTab;
            const Icon = tab.icon;
            const accent = DETECTION_WORKSPACE_ACCENTS[tab.key] || DETECTION_WORKSPACE_ACCENTS.sigma;
            return (
              <button
                key={tab.key}
                type="button"
                onClick={() => setTab(tab.key)}
                className="flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-colors"
                style={detectionWorkspaceTabStyle(selected, accent)}
              >
                <Icon className="w-4 h-4" style={{ color: selected ? accent : '#a7c7d6' }} />
                {tab.label}
              </button>
            );
          })}
        </div>
        <p className="sophia-terminal-meta text-xs mt-3 px-1">{activeConfig.description}</p>
      </div>

      <div>{activeConfig.render()}</div>
    </div>
  );
}
