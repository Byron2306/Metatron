import { useSearchParams } from 'react-router-dom';
import { LayoutDashboard, ShieldAlert, Bell, AlertTriangle } from 'lucide-react';
import DashboardPage from './DashboardPage';
import CommandCenterPage from './CommandCenterPage';
import AlertsPage from './AlertsPage';
import ThreatsPage from './ThreatsPage';

const COMMAND_TABS = [
  {
    key: 'dashboard',
    label: 'Dashboard',
    description: 'Operational overview, key metrics, and command-level situational status.',
    icon: LayoutDashboard,
    render: () => <DashboardPage />,
  },
  {
    key: 'center',
    label: 'Command Center',
    description: 'Central command surface for high-priority triage and action orchestration.',
    icon: ShieldAlert,
    render: () => <CommandCenterPage />,
  },
  {
    key: 'alerts',
    label: 'Alerts',
    description: 'Alert queue and severity-driven triage workflow.',
    icon: Bell,
    render: () => <AlertsPage />,
  },
  {
    key: 'threats',
    label: 'Threats',
    description: 'Threat-centric view for active incidents and tactical response decisions.',
    icon: AlertTriangle,
    render: () => <ThreatsPage />,
  },
];

const DEFAULT_TAB = 'dashboard';

export default function CommandWorkspacePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const rawTab = (searchParams.get('tab') || DEFAULT_TAB).toLowerCase();
  const activeTab = COMMAND_TABS.some((tab) => tab.key === rawTab) ? rawTab : DEFAULT_TAB;
  const activeConfig = COMMAND_TABS.find((tab) => tab.key === activeTab) || COMMAND_TABS[0];

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
        <h1 className="text-2xl font-bold text-white">Command Workspace</h1>
        <p className="text-sm text-slate-400">
          Unified command surface for dashboard monitoring, alerts, threats, and command operations.
        </p>
      </div>

      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-2">
        <div className="flex flex-wrap gap-2">
          {COMMAND_TABS.map((tab) => {
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
                    ? { backgroundColor: 'rgba(56,189,248,0.2)', color: '#7dd3fc' }
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
