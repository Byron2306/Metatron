import { useSearchParams } from 'react-router-dom';
import { Mail, Server } from 'lucide-react';
import EmailProtectionPage from './EmailProtectionPage';
import EmailGatewayPage from './EmailGatewayPage';
import WorkspaceErrorBoundary from '../components/WorkspaceErrorBoundary';
import SeraphPageHeader from '../components/SeraphPageHeader';

const EMAIL_WORKSPACE_ACCENTS = {
  protection: '#ff8ad9',
  gateway: '#ffd166',
};

const emailWorkspacePanelStyle = (accent) => ({
  background: 'linear-gradient(160deg, rgba(8,18,34,0.92), rgba(3,9,18,0.96))',
  border: `1px solid ${accent}`,
  boxShadow: `0 0 14px ${accent}22, inset 0 0 8px rgba(255,255,255,0.02)`,
  borderRadius: '14px',
});

const emailWorkspaceTabStyle = (selected, accent) => ({
  background: selected ? `linear-gradient(135deg, ${accent}20, rgba(255,255,255,0.03))` : 'linear-gradient(135deg, rgba(8,20,38,0.82), rgba(4,11,22,0.9))',
  border: `1px solid ${selected ? `${accent}55` : 'rgba(115,163,185,0.16)'}`,
  color: selected ? '#f7fbff' : '#a7c7d6',
  boxShadow: selected ? `0 0 10px ${accent}18` : 'none',
  textTransform: 'uppercase',
  letterSpacing: '0.14em',
  fontFamily: "'FfMoon', 'Orbitron', sans-serif",
});

const EMAIL_SECURITY_TABS = [
  {
    key: 'protection',
    label: 'Protection',
    description: 'Mailbox and user-level protection, phishing analysis, and policy controls.',
    icon: Mail,
    render: () => <EmailProtectionPage />,
  },
  {
    key: 'gateway',
    label: 'Gateway',
    description: 'SMTP relay filtering, block/allow lists, and quarantine pipeline operations.',
    icon: Server,
    render: () => <EmailGatewayPage />,
  },
];

const DEFAULT_TAB = 'protection';

export default function EmailSecurityWorkspacePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const rawTab = (searchParams.get('tab') || DEFAULT_TAB).toLowerCase();
  const activeTab = EMAIL_SECURITY_TABS.some((tab) => tab.key === rawTab) ? rawTab : DEFAULT_TAB;
  const activeConfig = EMAIL_SECURITY_TABS.find((tab) => tab.key === activeTab) || EMAIL_SECURITY_TABS[0];

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
    <div className="p-6 space-y-6" data-accent="amber">
      <SeraphPageHeader
        eyebrow="seraph · email-security · message defense"
        title="Email Security"
        tagline="> consolidated workspace for email protection controls and gateway pipeline operations"
        accent="amber"
        status={activeConfig.label.toUpperCase()}
      />

      <div style={{ ...emailWorkspacePanelStyle(EMAIL_WORKSPACE_ACCENTS[activeTab] || EMAIL_WORKSPACE_ACCENTS.protection), padding: '0.7rem' }}>
        <div className="flex flex-wrap gap-2">
          {EMAIL_SECURITY_TABS.map((tab) => {
            const selected = tab.key === activeTab;
            const Icon = tab.icon;
            const accent = EMAIL_WORKSPACE_ACCENTS[tab.key] || EMAIL_WORKSPACE_ACCENTS.protection;
            return (
              <button
                key={tab.key}
                type="button"
                onClick={() => setTab(tab.key)}
                className="flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-colors"
                style={emailWorkspaceTabStyle(selected, accent)}
              >
                <Icon className="w-4 h-4" style={{ color: selected ? accent : '#a7c7d6' }} />
                {tab.label}
              </button>
            );
          })}
        </div>
        <p className="sophia-terminal-meta text-xs mt-3 px-1">{activeConfig.description}</p>
      </div>

      <WorkspaceErrorBoundary title="Email Security workspace unavailable">
        <div>{activeConfig.render()}</div>
      </WorkspaceErrorBoundary>
    </div>
  );
}
