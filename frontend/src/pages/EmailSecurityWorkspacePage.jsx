import { useSearchParams } from 'react-router-dom';
import { Mail, Server } from 'lucide-react';
import EmailProtectionPage from './EmailProtectionPage';
import EmailGatewayPage from './EmailGatewayPage';
import WorkspaceErrorBoundary from '../components/WorkspaceErrorBoundary';

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
    <div className="p-6 space-y-6">
      <div className="space-y-2">
        <h1 className="text-2xl font-bold text-white">Email Security</h1>
        <p className="text-sm text-slate-400">
          Consolidated workspace for email protection controls and gateway pipeline operations.
        </p>
      </div>

      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-2">
        <div className="flex flex-wrap gap-2">
          {EMAIL_SECURITY_TABS.map((tab) => {
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
                    ? { backgroundColor: 'rgba(14,165,233,0.18)', color: '#7dd3fc' }
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

      <WorkspaceErrorBoundary title="Email Security workspace unavailable">
        <div>{activeConfig.render()}</div>
      </WorkspaceErrorBoundary>
    </div>
  );
}
