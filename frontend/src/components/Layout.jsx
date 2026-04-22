import { useEffect, useState } from 'react';
import { Outlet, NavLink, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  LayoutDashboard,
  LogOut,
  ChevronRight,
  Cpu,
  Activity,
  Network,
  Crosshair,
  Radar,
  FileText,
  ShieldAlert,
  Settings,
  Clock,
  ScrollText,
  Container,
  Lock,
  GitBranch,
  Brain,
  Workflow,
  Key,
  ShieldCheck,
  Box,
  Globe,
  BarChart3,
  Terminal,
  Radio,
  Map,
  Mail,
  Chrome,
  Server,
  Cloud,
  Eye,
  FlaskConical,
  Fingerprint,
  Smartphone,
  Link,
  Shield,
  Sparkles
} from 'lucide-react';
import { Button } from './ui/button';
import triunePages from '../triune_pages_map';

const NAV_SECTIONS = [
  {
    id: 'sophia',
    title: 'Sophia · ARDA OS',
    defaultOpen: true,
    items: [
      { path: '/sophia', icon: Sparkles, label: 'Sophia Dashboard' },
      { path: '/sophia-chat', icon: Brain, label: 'Sophia Chat', external: true, url: '__SOPHIA_CHAT__' },
      { path: '/arda-desktop', icon: Shield, label: 'ARDA Desktop', external: true, url: '__ARDA_DESKTOP__' },
      { path: '/kernel-sensors', icon: Cpu, label: 'Kernel Sensors' },
      { path: '/secure-boot', icon: Shield, label: 'Secure Boot' },
      { path: '/advanced', icon: Cpu, label: 'Advanced Services' },
    ],
  },
  {
    id: 'command',
    title: 'Command',
    defaultOpen: true,
    items: [
      { path: '/command', icon: LayoutDashboard, label: 'Command Workspace' },
      { path: '/timeline', icon: Clock, label: 'Timeline' },
    ],
  },
  {
    id: 'intelligence',
    title: 'Intelligence',
    defaultOpen: true,
    items: [
      { path: '/world', icon: Brain, label: 'World View' },
      { path: '/investigation', icon: GitBranch, label: 'Investigation' },
      { path: '/ai-activity', icon: Brain, label: 'AI Activity' },
      { path: '/hunting', icon: Crosshair, label: 'Threat Hunting' },
      { path: '/network', icon: Network, label: 'Network Map' },
      { path: '/honeypots', icon: Radar, label: 'Honeypots' },
    ],
  },
  {
    id: 'response',
    title: 'Response',
    defaultOpen: true,
    items: [
      { path: '/unified-agent', icon: Cpu, label: 'Unified Agent' },
      { path: '/agent-dashboard', icon: Link, label: 'Agent Dashboard', external: true, url: '__AGENT_UI__' },
      { path: '/response-operations', icon: Workflow, label: 'Response Operations' },
      { path: '/deception', icon: Eye, label: 'Deception' },
      { path: '/honey-tokens', icon: Key, label: 'Honey Tokens' },
      { path: '/ransomware', icon: ShieldAlert, label: 'Ransomware' },
    ],
  },
  {
    id: 'platform',
    title: 'Platform',
    defaultOpen: true,
    items: [
      { path: '/identity', icon: Fingerprint, label: 'Identity' },
      { path: '/zero-trust', icon: ShieldCheck, label: 'Zero Trust' },
      { path: '/vpn', icon: Lock, label: 'VPN' },
      { path: '/cspm', icon: Cloud, label: 'Cloud Security' },
      { path: '/containers', icon: Container, label: 'Containers' },
      { path: '/browser-isolation', icon: Globe, label: 'Browser Isolation' },
      { path: '/email-security', icon: Mail, label: 'Email Security' },
      { path: '/endpoint-mobility', icon: Smartphone, label: 'Endpoint Mobility' },
    ],
  },
  {
    id: 'engineering',
    title: 'Engineering',
    defaultOpen: false,
    items: [
      { path: '/detection-engineering', icon: FlaskConical, label: 'Detection Engineering' },
      { path: '/zeek', icon: Radio, label: 'Zeek NDR' },
      { path: '/osquery-fleet', icon: Terminal, label: 'osquery / Fleet' },
      { path: '/ml-prediction', icon: Brain, label: 'ML Prediction' },
      { path: '/sandbox', icon: Box, label: 'Sandbox' },
    ],
  },
  {
    id: 'admin',
    title: 'Admin',
    defaultOpen: false,
    items: [
      { path: '/reports', icon: FileText, label: 'Reports' },
      { path: '/audit', icon: ScrollText, label: 'Audit Logs' },
      { path: '/tenants', icon: Globe, label: 'Tenants' },
      { path: '/settings', icon: Settings, label: 'Settings' },
    ],
  },
  {
    id: 'more-tools',
    title: 'More Tools',
    defaultOpen: true,
    items: [
      { path: '/heatmap', icon: Map, label: 'Threat Heatmap' },
      { path: '/vns-alerts', icon: Mail, label: 'VNS Alerts' },
      { path: '/browser-extension', icon: Chrome, label: 'Browser Extension' },
      { path: '/kibana', icon: BarChart3, label: 'Kibana' },
      { path: '/setup-guide', icon: Server, label: 'Setup Guide' },
    ],
  },
];

const Layout = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  // Seraph AI Logo URL
  const logoUrl = "https://customer-assets.emergentagent.com/job_securityshield-17/artifacts/4jbqdhyd_ChatGPT%20Image%20Feb%2010%2C%202026%2C%2009_07_51%20AM.png";

  const [openSections, setOpenSections] = useState(() =>
    NAV_SECTIONS.reduce((acc, section) => {
      const hasActive = section.items.some(
        (item) => !item.external && location.pathname.startsWith(item.path),
      );
      acc[section.id] = section.defaultOpen || hasActive;
      return acc;
    }, {}),
  );

  useEffect(() => {
    setOpenSections((prev) => {
      const next = { ...prev };
      for (const section of NAV_SECTIONS) {
        const hasActive = section.items.some(
          (item) => !item.external && location.pathname.startsWith(item.path),
        );
        if (hasActive) {
          next[section.id] = true;
        } else if (next[section.id] === undefined) {
          next[section.id] = section.defaultOpen;
        }
      }
      return next;
    });
  }, [location.pathname]);

  const toggleSection = (sectionId) => {
    setOpenSections((prev) => ({ ...prev, [sectionId]: !prev[sectionId] }));
  };

  const resolveTriuneRoles = (item) => {
    const labelKey = item.label.replace(/[^A-Za-z0-9]/g, '') + 'Page';
    const altKey = item.label.replace(/\s+/g, '') + 'Page';
    const simpleKey = item.path.replace(/\//g, '');
    return (
      triunePages[labelKey] ||
      triunePages[altKey] ||
      triunePages[item.label] ||
      triunePages[simpleKey] ||
      []
    );
  };

  const renderNavItem = (item) => {
    if (item.external) {
      const resolvedExternalUrl = item.url === '__AGENT_UI__'
        ? `${window.location.protocol}//${window.location.hostname}:5000`
        : item.url === '__SOPHIA_CHAT__'
        ? `${window.location.protocol}//${window.location.hostname}:7070`
        : item.url === '__ARDA_DESKTOP__'
        ? `${window.location.protocol}//${window.location.hostname}:8082`
        : item.url;
      return (
        <a
          key={item.path}
          href={resolvedExternalUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-3 px-4 py-2.5 rounded-lg transition-all duration-200 group seraph-nav-item"
          style={{ color: '#A5F3FC', border: '1px solid transparent' }}
        >
          <item.icon className="w-4 h-4" style={{ color: '#A5F3FC' }} />
          <span className="font-medium text-sm" style={{ color: '#A5F3FC' }}>
            {item.label}
          </span>
          <ChevronRight className="w-4 h-4 ml-auto" style={{ color: '#A5F3FC' }} />
        </a>
      );
    }

    return (
      <NavLink
        key={item.path}
        to={item.path}
        className={({ isActive }) =>
          `flex items-center gap-3 px-4 py-2.5 rounded-lg transition-all duration-200 group ${
            isActive ? 'seraph-nav-active' : 'seraph-nav-item'
          }`
        }
        style={({ isActive }) =>
          isActive
            ? {
                backgroundColor: 'rgba(56, 189, 248, 0.1)',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                color: '#38BDF8',
              }
            : {
                color: '#A5F3FC',
                border: '1px solid transparent',
              }
        }
      >
        {({ isActive }) => {
          const roles = resolveTriuneRoles(item);
          return (
            <>
              <item.icon className="w-4 h-4" style={{ color: isActive ? '#38BDF8' : '#A5F3FC' }} />
              <span className="font-medium text-sm" style={{ color: isActive ? '#E0E7FF' : '#A5F3FC' }}>
                {item.label}
                {roles.length ? (
                  <span style={{ marginLeft: 8, display: 'inline-flex', gap: 6 }}>
                    {roles.map((role) => (
                      <span
                        key={role}
                        style={{
                          fontSize: 10,
                          padding: '2px 6px',
                          borderRadius: 6,
                          background: 'rgba(255,255,255,0.04)',
                          color: '#A5F3FC',
                        }}
                      >
                        {role[0]}
                      </span>
                    ))}
                  </span>
                ) : null}
              </span>
              {isActive ? (
                <ChevronRight className="w-4 h-4 ml-auto" style={{ color: '#38BDF8' }} />
              ) : null}
            </>
          );
        }}
      </NavLink>
    );
  };

  return (
    <div className="min-h-screen flex" style={{ backgroundColor: '#0C1020' }}>
      {/* Sidebar */}
      <aside className="w-64 flex flex-col" style={{ backgroundColor: '#121833', borderRight: '2px solid rgba(253, 230, 138, 0.2)' }}>
        {/* Logo */}
        <div className="p-6" style={{ borderBottom: '2px solid rgba(253, 230, 138, 0.2)' }}>
          <div className="flex items-center gap-4">
            <div className="w-16 h-16 rounded-xl overflow-hidden" style={{ 
              background: 'linear-gradient(135deg, rgba(253, 230, 138, 0.3), rgba(56, 189, 248, 0.2))',
              boxShadow: '0 0 30px rgba(253, 230, 138, 0.4), inset 0 0 20px rgba(56, 189, 248, 0.1)',
              border: '2px solid rgba(253, 230, 138, 0.4)'
            }}>
              <img src={logoUrl} alt="Seraph AI" className="w-full h-full object-cover" />
            </div>
            <div>
              <h1 className="font-mono font-bold text-xl tracking-wider" style={{ color: '#FDE68A', textShadow: '0 0 15px rgba(253, 230, 138, 0.4)' }}>SERAPH AI</h1>
              <p className="text-xs" style={{ color: '#A5F3FC' }}>Seraphic Watch</p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-3 space-y-2 overflow-y-auto">
          {NAV_SECTIONS.map((section) => (
            <div key={section.id} className="space-y-1">
              <button
                type="button"
                onClick={() => toggleSection(section.id)}
                className="w-full flex items-center justify-between px-2 py-1 rounded-md transition-colors"
                style={{
                  color: '#FDE68A',
                  backgroundColor: 'rgba(253, 230, 138, 0.06)',
                  border: '1px solid rgba(253, 230, 138, 0.16)',
                }}
              >
                <span className="text-xs font-semibold uppercase tracking-widest">
                  {section.title}
                </span>
                <ChevronRight
                  className="w-4 h-4 transition-transform duration-200"
                  style={{
                    color: '#FDE68A',
                    transform: openSections[section.id] ? 'rotate(90deg)' : 'rotate(0deg)',
                  }}
                />
              </button>
              {openSections[section.id] ? (
                <div className="space-y-0.5">
                  {section.items.map((item) => renderNavItem(item))}
                </div>
              ) : null}
            </div>
          ))}
        </nav>

        {/* System Status */}
        <div className="p-4" style={{ borderTop: '2px solid rgba(253, 230, 138, 0.2)' }}>
          <div className="rounded-xl p-4" style={{ backgroundColor: 'rgba(253, 230, 138, 0.08)', border: '1px solid rgba(253, 230, 138, 0.2)' }}>
            <div className="flex items-center gap-2 mb-2">
              <Activity className="w-5 h-5" style={{ color: '#FDE68A' }} />
              <span className="text-sm font-medium" style={{ color: '#FDE68A' }}>Seraphic Status</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full animate-pulse" style={{ backgroundColor: '#FDE68A', boxShadow: '0 0 15px #FDE68A' }} />
              <span className="text-sm font-mono font-bold" style={{ color: '#FDE68A' }}>WATCHING</span>
            </div>
          </div>
        </div>

        {/* User Section */}
        <div className="p-4" style={{ borderTop: '2px solid rgba(253, 230, 138, 0.2)' }}>
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ backgroundColor: 'rgba(253, 230, 138, 0.15)', border: '2px solid rgba(253, 230, 138, 0.4)' }}>
              <span className="text-lg font-mono font-bold" style={{ color: '#FDE68A' }}>
                {user?.name?.charAt(0)?.toUpperCase() || 'U'}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-white truncate">{user?.name}</p>
              <p className="text-xs truncate" style={{ color: '#A5F3FC' }}>{user?.role}</p>
            </div>
          </div>
          <Button
            onClick={handleLogout}
            variant="ghost"
            className="w-full justify-start text-slate-400 hover:text-red-400 hover:bg-red-500/10"
            data-testid="logout-btn"
          >
            <LogOut className="w-4 h-4 mr-2" />
            Logout
          </Button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto" style={{ backgroundColor: '#0C1020' }}>
        <Outlet />
      </main>
    </div>
  );
};

export default Layout;
