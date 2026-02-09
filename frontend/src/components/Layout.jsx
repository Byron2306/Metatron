import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { 
  LayoutDashboard, 
  Shield, 
  Bell, 
  AlertTriangle, 
  LogOut, 
  ChevronRight,
  Cpu,
  Activity,
  Network,
  Crosshair,
  Radar,
  FileText
} from 'lucide-react';
import { Button } from './ui/button';

const Layout = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const navItems = [
    { path: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
    { path: '/ai-detection', icon: Cpu, label: 'AI Detection' },
    { path: '/threats', icon: AlertTriangle, label: 'Threats' },
    { path: '/alerts', icon: Bell, label: 'Alerts' },
    { path: '/network', icon: Network, label: 'Network Map' },
    { path: '/hunting', icon: Crosshair, label: 'Threat Hunting' },
    { path: '/honeypots', icon: Radar, label: 'Honeypots' },
    { path: '/reports', icon: FileText, label: 'Reports' },
  ];

  return (
    <div className="min-h-screen bg-slate-950 flex">
      {/* Sidebar */}
      <aside className="w-64 bg-slate-900/80 backdrop-blur-xl border-r border-slate-800 flex flex-col">
        {/* Logo */}
        <div className="p-6 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded bg-blue-500/20 flex items-center justify-center">
              <Shield className="w-6 h-6 text-blue-500" />
            </div>
            <div>
              <h1 className="font-mono font-bold text-white text-sm">DEFENDER</h1>
              <p className="text-xs text-slate-500">Anti-AI Defense</p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-3 rounded transition-all duration-200 group ${
                  isActive
                    ? 'bg-blue-500/10 text-blue-400 border border-blue-500/30'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <item.icon className={`w-5 h-5 ${isActive ? 'text-blue-400' : ''}`} />
                  <span className="font-medium text-sm">{item.label}</span>
                  {isActive && (
                    <ChevronRight className="w-4 h-4 ml-auto text-blue-400" />
                  )}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        {/* System Status */}
        <div className="p-4 border-t border-slate-800">
          <div className="bg-slate-800/50 rounded p-3">
            <div className="flex items-center gap-2 mb-2">
              <Activity className="w-4 h-4 text-green-400" />
              <span className="text-xs text-slate-400">System Status</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
              <span className="text-xs text-green-400 font-mono">OPERATIONAL</span>
            </div>
          </div>
        </div>

        {/* User Section */}
        <div className="p-4 border-t border-slate-800">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-8 h-8 rounded bg-slate-700 flex items-center justify-center">
              <span className="text-sm font-mono text-white">
                {user?.name?.charAt(0)?.toUpperCase() || 'U'}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm text-white truncate">{user?.name}</p>
              <p className="text-xs text-slate-500 truncate">{user?.role}</p>
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
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
};

export default Layout;
