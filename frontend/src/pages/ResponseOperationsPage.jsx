import { useSearchParams } from 'react-router-dom';
import { ShieldAlert, Shield, Workflow, Zap } from 'lucide-react';
import ThreatResponsePage from './ThreatResponsePage';
import EDRPage from './EDRPage';
import SOARPage from './SOARPage';
import QuarantinePage from './QuarantinePage';
import SeraphPageHeader from '../components/SeraphPageHeader';

const RESPONSE_ACCENTS = {
  automation: '#ff8ad9',
  edr: '#7ce2a3',
  soar: '#c5a2eb',
  quarantine: '#ffd166',
};

const responseWorkspacePanelStyle = (accent) => ({
  background: 'linear-gradient(160deg, rgba(8,18,34,0.92), rgba(3,9,18,0.96))',
  border: `1px solid ${accent}`,
  boxShadow: `0 0 14px ${accent}22, inset 0 0 8px rgba(255,255,255,0.02)`,
  borderRadius: '14px',
});

const responseWorkspaceTabStyle = (selected, accent) => ({
  background: selected ? `linear-gradient(135deg, ${accent}20, rgba(255,255,255,0.03))` : 'linear-gradient(135deg, rgba(8,20,38,0.82), rgba(4,11,22,0.9))',
  border: `1px solid ${selected ? `${accent}55` : 'rgba(115,163,185,0.16)'}`,
  color: selected ? '#f7fbff' : '#a7c7d6',
  boxShadow: selected ? `0 0 10px ${accent}18` : 'none',
  textTransform: 'uppercase',
  letterSpacing: '0.14em',
  fontFamily: "'FfMoon', 'Orbitron', sans-serif",
});

const RESPONSE_TABS = [
  {
    key: 'automation',
    label: 'Automated Response',
    description: 'Threat-response controls, auto-block, and incident response history.',
    icon: Zap,
    render: () => <ThreatResponsePage />,
  },
  {
    key: 'edr',
    label: 'EDR',
    description: 'Endpoint telemetry, FIM controls, process tree, and USB policy.',
    icon: Shield,
    render: () => <EDRPage />,
  },
  {
    key: 'soar',
    label: 'SOAR',
    description: 'Playbook execution and orchestration pipelines.',
    icon: Workflow,
    render: () => <SOARPage />,
  },
  {
    key: 'quarantine',
    label: 'Quarantine',
    description: 'File isolation lifecycle management and restore/delete operations.',
    icon: ShieldAlert,
    render: () => <QuarantinePage />,
  },
];

const DEFAULT_TAB = 'automation';

export default function ResponseOperationsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const rawTab = (searchParams.get('tab') || DEFAULT_TAB).toLowerCase();
  const activeTab = RESPONSE_TABS.some((tab) => tab.key === rawTab) ? rawTab : DEFAULT_TAB;
  const activeConfig = RESPONSE_TABS.find((tab) => tab.key === activeTab) || RESPONSE_TABS[0];

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
    <div className="p-6 space-y-6" data-accent="green">
      <SeraphPageHeader
        eyebrow="seraph · response-ops · containment workflows"
        title="Response Operations"
        tagline="> unified response workspace across automation, EDR, SOAR, and quarantine"
        accent="green"
        status={activeConfig.label.toUpperCase()}
      />

      <div style={{ ...responseWorkspacePanelStyle(RESPONSE_ACCENTS[activeTab] || RESPONSE_ACCENTS.automation), padding: '0.7rem' }}>
        <div className="flex flex-wrap gap-2">
          {RESPONSE_TABS.map((tab) => {
            const selected = tab.key === activeTab;
            const Icon = tab.icon;
            const accent = RESPONSE_ACCENTS[tab.key] || RESPONSE_ACCENTS.automation;
            return (
              <button
                key={tab.key}
                type="button"
                onClick={() => setTab(tab.key)}
                className="flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-colors"
                style={responseWorkspaceTabStyle(selected, accent)}
              >
                <Icon className="w-4 h-4" style={{ color: selected ? accent : '#a7c7d6' }} />
                {tab.label}
              </button>
            );
          })}
        </div>
        <p className="sophia-terminal-meta text-xs mt-3 px-1">{activeConfig.description}</p>
      </div>

      <div className="seraph-nested-workspace">{activeConfig.render()}</div>
    </div>
  );
}
