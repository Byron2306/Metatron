import { useSearchParams } from 'react-router-dom';
import { useEffect, useMemo, useState } from 'react';
import { LayoutDashboard, ShieldAlert, Bell, AlertTriangle, MonitorSmartphone, Users, Smartphone, Mail, Zap, ServerCrash, Activity } from 'lucide-react';
import { motion } from 'framer-motion';
import { useAuth } from '../context/AuthContext';
import DashboardPage from './DashboardPage';
import CommandCenterPage from './CommandCenterPage';
import AlertsPage from './AlertsPage';
import ThreatsPage from './ThreatsPage';
import SeraphPageHeader from '../components/SeraphPageHeader';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const COMMAND_WORKSPACE_ACCENTS = {
  cyan: '#00f0ff',
  pink: '#ff35f4',
  green: '#39ff14',
  purple: '#bc13fe',
  yellow: '#fff200',
  orange: '#ff8a00',
  red: '#ff174d',
};

const workspacePanelStyle = (accent) => ({
  background: 'linear-gradient(160deg, rgba(9,18,38,0.88), rgba(2,8,19,0.94))',
  border: `3px solid ${accent}88`,
  boxShadow: `0 0 8px ${accent}2f, 0 0 18px ${accent}17, inset 0 0 14px ${accent}12`,
  clipPath: 'polygon(10px 0, 100% 0, 100% calc(100% - 10px), calc(100% - 10px) 100%, 0 100%, 0 10px)',
});

const workspaceTabStyle = (selected, accent) => ({
  background: selected
    ? `linear-gradient(135deg, ${accent}28, ${accent}12)`
    : 'linear-gradient(135deg, rgba(8,20,38,0.88), rgba(4,11,22,0.94))',
  border: `2px solid ${selected ? accent : 'rgba(115,163,185,0.28)'}`,
  color: selected ? '#f7fbff' : '#9ccbdd',
  boxShadow: selected ? `0 0 8px ${accent}32, inset 0 0 10px ${accent}14` : 'none',
  textTransform: 'uppercase',
  letterSpacing: '0.16em',
  fontFamily: "'FfMoon', 'JetBrains Mono', monospace",
});

function EnrollmentOperationsPanel() {
  const { token } = useAuth();
  const [events, setEvents] = useState([]);
  const [devices, setDevices] = useState([]);
  const [agents, setAgents] = useState([]);
  const [mobileDevices, setMobileDevices] = useState([]);
  const [protectedUsers, setProtectedUsers] = useState({ executives: [], vip_users: [] });

  useEffect(() => {
    const headers = { Authorization: `Bearer ${token}` };
    Promise.all([
      fetch(`${API}/unified/enrollment/events?limit=50`, { headers }),
      fetch(`${API}/unified/enrollment/devices?limit=50`, { headers }),
      fetch(`${API}/unified/agents?limit=200&full=false`, { headers }),
      fetch(`${API}/mobile-security/devices`, { headers }),
      fetch(`${API}/email-protection/protected-users`, { headers }),
    ]).then(async ([eventRes, deviceRes, agentsRes, mobileRes, protectedRes]) => {
      if (eventRes.ok) setEvents((await eventRes.json()).events || []);
      if (deviceRes.ok) setDevices((await deviceRes.json()).devices || []);
      if (agentsRes.ok) setAgents((await agentsRes.json()).agents || []);
      if (mobileRes.ok) setMobileDevices((await mobileRes.json()).devices || []);
      if (protectedRes.ok) setProtectedUsers(await protectedRes.json());
    }).catch(() => {});
  }, [token]);

  const protectedCount = (protectedUsers.executives?.length || 0) + (protectedUsers.vip_users?.length || 0);

  // Severity classifier so each event log row gets a colored left bar +
  // small pulsing icon — same grammar as the threats / alerts list.
  const severityOf = (event) => {
    const s = String(event?.severity || event?.event_type || '').toLowerCase();
    if (/critical|fail|breach|compromise/.test(s)) return 'critical';
    if (/error|denied|block|suspicious/.test(s)) return 'high';
    if (/warn|stale|missing/.test(s)) return 'medium';
    if (/register|enroll|deploy|install|approved/.test(s)) return 'success';
    return 'info';
  };
  const sevPalette = {
    critical: { color: '#ff2bd6', glow: 'rgba(255,43,214,0.55)', icon: ServerCrash },
    high:     { color: '#ff3838', glow: 'rgba(239,68,68,0.55)',  icon: AlertTriangle },
    medium:   { color: '#39ff14', glow: 'rgba(57,255,20,0.5)',  icon: AlertTriangle },
    success:  { color: '#39ff14', glow: 'rgba(57,255,20,0.5)',   icon: Zap },
    info:     { color: '#00f0ff', glow: 'rgba(0,240,255,0.45)',  icon: Zap },
  };

  const StatCard = ({ label, value, color, accent, icon: Icon }) => (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ y: -2 }}
      className="seraph-fx-hover-lift"
      style={{
        background: 'linear-gradient(160deg, rgba(9,18,38,0.86), rgba(2,8,19,0.94))',
        border: `1px solid ${accent}55`,
        borderLeft: `3px solid ${accent}`,
        clipPath: 'polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px)',
        padding: '1rem 1.1rem',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="sophia-scan sophia-terminal-label" style={{ fontSize: 10, letterSpacing: '0.32em' }}>
            {label}
          </p>
          <p className="sophia-flicker sophia-terminal-value" style={{
            fontWeight: 900,
            fontSize: '2.2rem',
            color,
            textShadow: `0 0 12px ${accent}99, 0 0 24px ${accent}44`,
            lineHeight: 1,
            marginTop: 4,
          }}>
            {value}
          </p>
        </div>
        {Icon ? (
          <Icon className="seraph-fx-pulse-pip" style={{
            width: 22,
            height: 22,
            color: accent,
            filter: `drop-shadow(0 0 8px ${accent})`,
          }} />
        ) : null}
      </div>
    </motion.div>
  );

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard label="Pre-enrolled Devices" value={devices.length} color="#00f0ff" accent="#00f0ff" icon={MonitorSmartphone} />
        <StatCard label="Registration Events" value={events.length} color="#39ff14" accent="#39ff14" icon={Zap} />
        <StatCard label="Unified Agents" value={agents.length} color="#bc13fe" accent="#bc13fe" icon={Users} />
        <StatCard label="Mobile + Email Protected" value={mobileDevices.length + protectedCount} color="#ff35f4" accent="#ff35f4" icon={Mail} />
      </div>

      <div className="sophia-hud-corners sophia-edge-sweep sophia-panel-glow" style={workspacePanelStyle('rgba(0,240,255,0.58)')}>
        <div className="flex items-center justify-between px-4 pt-4 pb-3" style={{ borderBottom: '1px solid rgba(0,240,255,0.16)' }}>
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4" style={{ color: '#00f0ff', filter: 'drop-shadow(0 0 6px rgba(0,240,255,0.55))' }} />
            <p className="sophia-terminal-heading text-sm">Enrollment / Agent Telemetry</p>
          </div>
          <p className="sophia-terminal-meta text-xs">Operational mesh view</p>
        </div>

        {events.length === 0 ? (
          <p className="p-4 text-sm text-slate-400">No enrollment or agent registration events yet.</p>
        ) : events.map((event, idx) => {
          const sev = sevPalette[severityOf(event)] || sevPalette.info;
          const Icon = sev.icon;
          return (
            <motion.div
              key={event.event_id || `${event.timestamp}-${event.message}-${idx}`}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: Math.min(idx * 0.025, 0.6) }}
              className="flex items-start justify-between gap-4 p-4"
              style={{
                borderBottom: '1px solid rgba(0,240,255,0.08)',
                borderLeft: `3px solid ${sev.color}`,
              }}
            >
              <div className="flex items-start gap-3 flex-1 min-w-0">
                <Icon
                  className={severityOf(event) === 'critical' || severityOf(event) === 'high' ? 'seraph-fx-pulse-pip' : ''}
                  style={{
                    width: 18,
                    height: 18,
                    flexShrink: 0,
                    color: sev.color,
                    filter: `drop-shadow(0 0 6px ${sev.glow})`,
                    marginTop: 2,
                  }}
                />
                <div className="flex-1 min-w-0">
                  <p className="sophia-flicker sophia-terminal-value text-sm" style={{ color: '#e6fbff' }}>
                    {event.message || event.event_type}
                  </p>
                  <p className="sophia-terminal-meta text-xs" style={{ marginTop: 2 }}>
                    <span style={{ color: sev.color, textShadow: `0 0 6px ${sev.glow}` }}>
                      {(event.platform || 'unknown').toUpperCase()}
                    </span>
                    {event.agent_id ? <> · {event.agent_id}</> : null}
                  </p>
                </div>
              </div>
              <span className="sophia-terminal-meta text-xs" style={{ whiteSpace: 'nowrap' }}>
                {event.timestamp ? new Date(event.timestamp).toLocaleString() : ''}
              </span>
            </motion.div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="sophia-hud-corners sophia-edge-sweep" style={workspacePanelStyle(COMMAND_WORKSPACE_ACCENTS.pink)}>
          <div className="flex items-center gap-2 p-4" style={{ borderBottom: '1px solid rgba(255,43,214,0.16)' }}>
            <Users className="h-4 w-4" style={{ color: COMMAND_WORKSPACE_ACCENTS.pink, filter: 'drop-shadow(0 0 6px rgba(255,43,214,0.45))' }} />
            <p className="sophia-terminal-heading text-sm">Unified Agents</p>
          </div>
          <div className="p-4 space-y-2 max-h-72 overflow-auto">
            {agents.map((agent) => (
              <div
                key={agent.agent_id}
                className="flex items-center justify-between rounded-md p-3"
                style={{
                  background: 'linear-gradient(140deg, rgba(12,10,26,0.9), rgba(5,10,20,0.95))',
                  border: '1px solid rgba(255,43,214,0.18)',
                  boxShadow: 'inset 0 0 12px rgba(255,43,214,0.05)',
                }}
              >
                <div>
                  <p className="sophia-flicker sophia-terminal-value text-sm" style={{ color: '#e6fbff' }}>{agent.hostname || agent.agent_id}</p>
                  <p className="sophia-terminal-meta text-xs">{agent.platform || 'unknown'} • {agent.status || 'unknown'}</p>
                </div>
                <span className="sophia-terminal-meta text-xs">{agent.agent_id}</span>
              </div>
            ))}
            {agents.length === 0 && <p className="sophia-terminal-meta text-sm">No agents registered.</p>}
          </div>
        </div>

        <div className="sophia-hud-corners sophia-edge-sweep" style={workspacePanelStyle(COMMAND_WORKSPACE_ACCENTS.cyan)}>
          <div className="flex items-center gap-2 p-4" style={{ borderBottom: '1px solid rgba(0,240,255,0.16)' }}>
            <Smartphone className="h-4 w-4" style={{ color: COMMAND_WORKSPACE_ACCENTS.cyan, filter: 'drop-shadow(0 0 6px rgba(0,240,255,0.45))' }} />
            <p className="sophia-terminal-heading text-sm">Mobile Devices + Email Protection</p>
          </div>
          <div className="p-4 space-y-3 max-h-72 overflow-auto">
            <div>
              <p className="sophia-terminal-label mb-2 text-xs">Mobile Devices</p>
              {mobileDevices.map((device) => (
                <div
                  key={device.device_id || device.serial_number}
                  className="flex items-center justify-between rounded-md p-3 mb-2"
                  style={{
                    background: 'linear-gradient(140deg, rgba(8,20,38,0.9), rgba(3,9,18,0.96))',
                    border: '1px solid rgba(0,240,255,0.16)',
                  }}
                >
                  <div>
                    <p className="sophia-flicker sophia-terminal-value text-sm" style={{ color: '#e6fbff' }}>{device.device_name}</p>
                    <p className="sophia-terminal-meta text-xs">{device.platform || 'unknown'} • {device.user_email || 'no email'}</p>
                  </div>
                  <span className="sophia-terminal-meta text-xs">{device.status || 'unknown'}</span>
                </div>
              ))}
              {mobileDevices.length === 0 && <p className="sophia-terminal-meta text-sm">No mobile devices enrolled.</p>}
            </div>
            <div>
              <p className="sophia-terminal-label mb-2 text-xs">Protected Users</p>
              {protectedUsers.executives?.map((exec) => (
                <div
                  key={exec.email}
                  className="flex items-center justify-between rounded-md p-3 mb-2"
                  style={{
                    background: 'linear-gradient(140deg, rgba(22,18,8,0.9), rgba(8,10,18,0.96))',
                    border: '1px solid rgba(255,43,214,0.22)',
                  }}
                >
                  <div>
                    <p className="sophia-flicker sophia-terminal-value text-sm" style={{ color: '#e6fbff' }}>{exec.email}</p>
                    <p className="sophia-terminal-meta text-xs">{exec.name || exec.title || 'Executive'}</p>
                  </div>
                  <Mail className="h-4 w-4" style={{ color: '#ff35f4', filter: 'drop-shadow(0 0 8px rgba(255,43,214,0.68))' }} />
                </div>
              ))}
              {(protectedUsers.vip_users || []).map((email) => (
                <div
                  key={email}
                  className="flex items-center justify-between rounded-md p-3 mb-2"
                  style={{
                    background: 'linear-gradient(140deg, rgba(22,18,8,0.9), rgba(8,10,18,0.96))',
                    border: '1px solid rgba(255,43,214,0.22)',
                  }}
                >
                  <p className="sophia-flicker sophia-terminal-value text-sm" style={{ color: '#e6fbff' }}>{email}</p>
                  <Mail className="h-4 w-4" style={{ color: '#ff35f4', filter: 'drop-shadow(0 0 8px rgba(255,43,214,0.68))' }} />
                </div>
              ))}
              {protectedCount === 0 && <p className="sophia-terminal-meta text-sm">No protected users configured.</p>}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

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
    key: 'enrollment',
    label: 'Enrollment',
    description: 'Unified agent enrollments, installer issuance, and registration audit events.',
    icon: MonitorSmartphone,
    render: () => <EnrollmentOperationsPanel />,
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
    <div className="p-6 space-y-6 sophia-isolated" data-testid="command-workspace-page" data-accent="gold">
      <SeraphPageHeader
        eyebrow="seraph · command · operational mesh"
        title="Command Workspace"
        tagline="> unified command surface for dashboard monitoring, alerts, threats, and command operations"
        accent="gold"
        status={activeConfig.label.toUpperCase()}
      />

      <div className="sophia-hud-corners sophia-edge-sweep sophia-panel-glow command-workspace-nav" style={{ ...workspacePanelStyle(COMMAND_WORKSPACE_ACCENTS.orange), padding: '0.85rem' }}>
        <div className="flex flex-wrap gap-2">
          {COMMAND_TABS.map((tab) => {
            const selected = tab.key === activeTab;
            const Icon = tab.icon;
            const accent = tab.key === 'threats'
              ? COMMAND_WORKSPACE_ACCENTS.red
              : tab.key === 'alerts'
                ? COMMAND_WORKSPACE_ACCENTS.yellow
                : tab.key === 'enrollment'
                  ? COMMAND_WORKSPACE_ACCENTS.green
                  : tab.key === 'center'
                    ? COMMAND_WORKSPACE_ACCENTS.orange
                    : COMMAND_WORKSPACE_ACCENTS.cyan;
            return (
              <button
                key={tab.key}
                data-tone={tab.key}
                type="button"
                onClick={() => setTab(tab.key)}
                className={`command-workspace-tab command-workspace-tab--${tab.key} flex items-center gap-2 px-3 py-2 rounded-md text-sm transition-colors`}
                style={workspaceTabStyle(selected, accent)}
              >
                <Icon className="w-4 h-4" style={{ color: selected ? accent : '#9ccbdd' }} />
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
