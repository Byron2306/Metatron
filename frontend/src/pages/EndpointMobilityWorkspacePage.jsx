import { useSearchParams } from 'react-router-dom';
import { Smartphone, Link } from 'lucide-react';
import MobileSecurityPage from './MobileSecurityPage';
import MDMConnectorsPage from './MDMConnectorsPage';
import WorkspaceErrorBoundary from '../components/WorkspaceErrorBoundary';
import SeraphPageHeader from '../components/SeraphPageHeader';

const ENDPOINT_WORKSPACE_ACCENTS = {
  mobile: '#7ce2a3',
  mdm: '#c5a2eb',
};

const endpointWorkspacePanelStyle = (accent) => ({
  background: 'linear-gradient(160deg, rgba(8,18,34,0.92), rgba(3,9,18,0.96))',
  border: `1px solid ${accent}`,
  boxShadow: `0 0 14px ${accent}22, inset 0 0 8px rgba(255,255,255,0.02)`,
  borderRadius: '14px',
});

const endpointWorkspaceTabStyle = (selected, accent) => ({
  background: selected ? `linear-gradient(135deg, ${accent}20, rgba(255,255,255,0.03))` : 'linear-gradient(135deg, rgba(8,20,38,0.82), rgba(4,11,22,0.9))',
  border: `1px solid ${selected ? `${accent}55` : 'rgba(115,163,185,0.16)'}`,
  color: selected ? '#f7fbff' : '#a7c7d6',
  boxShadow: selected ? `0 0 10px ${accent}18` : 'none',
  textTransform: 'uppercase',
  letterSpacing: '0.14em',
  fontFamily: "'FfMoon', 'Orbitron', sans-serif",
});

const ENDPOINT_MOBILITY_TABS = [
  {
    key: 'mobile',
    label: 'Mobile Security',
    description: 'Device posture, app analysis, and mobile threat telemetry.',
    icon: Smartphone,
    render: () => <MobileSecurityPage />,
  },
  {
    key: 'mdm',
    label: 'MDM Connectors',
    description: 'Enterprise MDM synchronization, policy pull, and remote action execution.',
    icon: Link,
    render: () => <MDMConnectorsPage />,
  },
];

const DEFAULT_TAB = 'mobile';

export default function EndpointMobilityWorkspacePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const rawTab = (searchParams.get('tab') || DEFAULT_TAB).toLowerCase();
  const activeTab = ENDPOINT_MOBILITY_TABS.some((tab) => tab.key === rawTab) ? rawTab : DEFAULT_TAB;
  const activeConfig = ENDPOINT_MOBILITY_TABS.find((tab) => tab.key === activeTab) || ENDPOINT_MOBILITY_TABS[0];

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
        eyebrow="seraph · endpoint-mobility · device posture"
        title="Endpoint Mobility"
        tagline="> unified endpoint mobility workspace across mobile security operations and MDM connectors"
        accent="green"
        status={activeConfig.label.toUpperCase()}
      />

      <div style={{ ...endpointWorkspacePanelStyle(ENDPOINT_WORKSPACE_ACCENTS[activeTab] || ENDPOINT_WORKSPACE_ACCENTS.mobile), padding: '0.7rem' }}>
        <div className="flex flex-wrap gap-2">
          {ENDPOINT_MOBILITY_TABS.map((tab) => {
            const selected = tab.key === activeTab;
            const Icon = tab.icon;
            const accent = ENDPOINT_WORKSPACE_ACCENTS[tab.key] || ENDPOINT_WORKSPACE_ACCENTS.mobile;
            return (
              <button
                key={tab.key}
                type="button"
                onClick={() => setTab(tab.key)}
                className="flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-colors"
                style={endpointWorkspaceTabStyle(selected, accent)}
              >
                <Icon className="w-4 h-4" style={{ color: selected ? accent : '#a7c7d6' }} />
                {tab.label}
              </button>
            );
          })}
        </div>
        <p className="sophia-terminal-meta text-xs mt-3 px-1">{activeConfig.description}</p>
      </div>

      <WorkspaceErrorBoundary title="Endpoint Mobility workspace unavailable">
        <div>{activeConfig.render()}</div>
      </WorkspaceErrorBoundary>
    </div>
  );
}
