import { useSearchParams } from 'react-router-dom';
import { Shield, FlaskConical, Radio } from 'lucide-react';
import SigmaPage from './SigmaPage';
import MitreAttackCoveragePage from './MitreAttackCoveragePage';
import AtomicValidationPage from './AtomicValidationPage';

const DETECTION_ENGINEERING_TABS = [
  {
    key: 'sigma',
    label: 'Sigma',
    description: 'Rule logic and detection content curation.',
    icon: Shield,
    render: () => <SigmaPage />,
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
      <div className="space-y-2">
        <h1 className="text-2xl font-bold text-white">Detection Engineering</h1>
        <p className="text-sm text-slate-400">
          Unified engineering workspace for rule authoring, ATT&CK coverage, and atomic validation.
        </p>
      </div>

      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-2">
        <div className="flex flex-wrap gap-2">
          {DETECTION_ENGINEERING_TABS.map((tab) => {
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
                    ? { backgroundColor: 'rgba(168,85,247,0.2)', color: '#d8b4fe' }
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
