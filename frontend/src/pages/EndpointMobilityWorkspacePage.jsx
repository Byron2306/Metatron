import { useSearchParams } from 'react-router-dom';
import { Smartphone, Link } from 'lucide-react';
import MobileSecurityPage from './MobileSecurityPage';
import MDMConnectorsPage from './MDMConnectorsPage';

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
      <div className="space-y-2">
        <h1 className="text-2xl font-bold text-white">Endpoint Mobility</h1>
        <p className="text-sm text-slate-400">
          Unified endpoint mobility workspace across mobile security operations and MDM connectors.
        </p>
      </div>

      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-2">
        <div className="flex flex-wrap gap-2">
          {ENDPOINT_MOBILITY_TABS.map((tab) => {
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
                    ? { backgroundColor: 'rgba(16,185,129,0.2)', color: '#6ee7b7' }
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
