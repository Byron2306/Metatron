import { useSearchParams } from 'react-router-dom';
import { ShieldAlert, Shield, Workflow, Zap } from 'lucide-react';
import ThreatResponsePage from './ThreatResponsePage';
import EDRPage from './EDRPage';
import SOARPage from './SOARPage';
import QuarantinePage from './QuarantinePage';

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
    <div className="p-6 space-y-6">
      <div className="space-y-2">
        <h1 className="text-2xl font-bold text-white">Response Operations</h1>
        <p className="text-sm text-slate-400">
          Unified response workspace across automation, EDR, SOAR, and quarantine.
        </p>
      </div>

      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-2">
        <div className="flex flex-wrap gap-2">
          {RESPONSE_TABS.map((tab) => {
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
                    ? { backgroundColor: 'rgba(14,165,164,0.2)', color: '#5eead4' }
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
