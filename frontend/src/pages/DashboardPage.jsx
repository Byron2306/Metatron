import { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Shield, 
  AlertTriangle, 
  Activity, 
  Cpu, 
  Target,
  Bug,
  Network,
  TrendingUp,
  Clock,
  ChevronRight,
  Zap
} from 'lucide-react';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell,
  Tooltip
} from 'recharts';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { ScrollArea } from '../components/ui/scroll-area';
import { toast } from 'sonner';
import SeraphPageHeader from '../components/SeraphPageHeader';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

// Spec-faithful — the keys now match the colors they paint. Previously
// COLOR_*.amber and COLOR_*.blue both held magenta RGB, which is why the
// Dashboard felt uniformly magenta no matter what color a card requested.
const COLOR_RGB = {
  red:     '255, 91, 91',
  green:   '57, 255, 20',
  amber:   '255, 176, 32',
  orange:  '255, 154, 31',
  yellow:  '253, 224, 71',
  cyan:    '0, 240, 255',
  magenta: '255, 43, 214',
  purple:  '124, 58, 237',
  gold:    '251, 191, 36',
  blue:    '0, 240, 255',
};

const COLOR_HEX = {
  red:     '#ff5b5b',
  green:   '#39ff9f',
  amber:   '#ffb020',
  orange:  '#ff9a1f',
  yellow:  '#fde047',
  cyan:    '#00f6ff',
  magenta: '#ff2bd6',
  purple:  '#bc13fe',
  gold:    '#fbbf24',
  blue:    '#7dd3fc',
};

const DASHBOARD_PANEL_ACCENTS = {
  magenta: { border: 'rgba(255,43,214,0.50)',  glow: 'rgba(255,43,214,0.18)',  title: '#ffb8e9', meta: '#ffd1f8' },
  cyan:    { border: 'rgba(0,240,255,0.50)',   glow: 'rgba(0,240,255,0.18)',   title: '#aef7ff', meta: '#dff8ff' },
  green:   { border: 'rgba(57,255,20,0.50)',   glow: 'rgba(57,255,20,0.18)',   title: '#b8ffca', meta: '#d8ffe8' },
  purple:  { border: 'rgba(124,58,237,0.50)',  glow: 'rgba(124,58,237,0.18)',  title: '#d6c4ff', meta: '#e0d6ff' },
  gold:    { border: 'rgba(251,191,36,0.50)',  glow: 'rgba(251,191,36,0.18)',  title: '#ffe9a8', meta: '#fff3c8' },
  amber:   { border: 'rgba(255,176,32,0.50)',  glow: 'rgba(255,176,32,0.18)',  title: '#ffd78a', meta: '#ffe0a8' },
  orange:  { border: 'rgba(255,154,31,0.50)',  glow: 'rgba(255,154,31,0.18)',  title: '#ffb38a', meta: '#ffd1b0' },
  yellow:  { border: 'rgba(253,224,71,0.50)',  glow: 'rgba(253,224,71,0.18)',  title: '#fff3a8', meta: '#fff8c8' },
  red:     { border: 'rgba(255,91,91,0.50)',   glow: 'rgba(255,91,91,0.18)',   title: '#ffd4d4', meta: '#ffe0e0' },
};

const dashboardPanelStyle = (accent) => ({
  background: 'linear-gradient(160deg, rgba(8,20,38,0.94), rgba(4,11,22,0.96))',
  border: `1px solid ${accent.border}`,
  boxShadow: `0 0 14px ${accent.glow}, inset 0 0 10px rgba(255,255,255,0.02)`,
  borderRadius: '14px',
});

// Rotate through the neon set so the dashboard no longer collapses into one hue.
const SOPHIA_BORDER_ROTATION = [
  'sophia-border-cyan',
  'sophia-border-green',
  'sophia-border-magenta',
  'sophia-border-orange',
  'sophia-border-yellow',
  'sophia-border-red',
];

const StatCard = ({ icon: Icon, label, value, subValue, color, glow, index = 0 }) => {
  const rgb = COLOR_RGB[color] || COLOR_RGB.blue;
  const hex = COLOR_HEX[color] || COLOR_HEX.blue;
  const borderClass = SOPHIA_BORDER_ROTATION[index % SOPHIA_BORDER_ROTATION.length];
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ y: -4 }}
      transition={{ type: 'spring', stiffness: 240, damping: 22 }}
      className={`sophia-card-glow rounded-lg p-4 ${borderClass}`}
      style={glow ? { boxShadow: `0 0 28px rgba(${rgb}, 0.32), 0 0 60px rgba(${rgb}, 0.18), inset 0 0 24px rgba(${rgb}, 0.08)` } : undefined}
    >
      <div className="flex items-start justify-between relative z-10">
        <div>
          <p className="sophia-scan sophia-terminal-label mb-2" style={{ fontSize: '0.7rem', letterSpacing: '0.32em', textTransform: 'uppercase' }}>
            {label}
          </p>
          <p
            className="sophia-flicker sophia-terminal-value text-3xl font-bold"
            style={{
              color: hex,
              textShadow: `0 0 10px rgba(${rgb}, 0.6), 0 0 22px rgba(${rgb}, 0.35)`,
            }}
          >
            {value}
          </p>
          {subValue && (
            <p className="sophia-terminal-meta text-xs mt-2" style={{ letterSpacing: '0.05em' }}>
              {subValue}
            </p>
          )}
        </div>
        <div
          className="w-11 h-11 flex items-center justify-center"
          style={{
            background: `linear-gradient(135deg, rgba(${rgb}, 0.18), rgba(${rgb}, 0.05))`,
            border: `1px solid rgba(${rgb}, 0.45)`,
            boxShadow: `0 0 14px rgba(${rgb}, 0.35), inset 0 0 10px rgba(${rgb}, 0.12)`,
            clipPath: 'polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px)',
          }}
        >
          <Icon className="w-5 h-5" style={{ color: hex, filter: `drop-shadow(0 0 6px rgba(${rgb}, 0.7))` }} />
        </div>
      </div>
    </motion.div>
  );
};

const SEVERITY_NEON = {
  critical: { hex: '#ff3b30', rgb: '255,59,48',    bg: 'rgba(255,59,48,0.07)'    },
  high:     { hex: '#ff7a1a', rgb: '255,122,26',   bg: 'rgba(255,122,26,0.07)'   },
  elevated: { hex: '#ff6a1f', rgb: '255,106,31',   bg: 'rgba(255,106,31,0.07)'   },
  warning:  { hex: '#ff8f1f', rgb: '255,143,31',   bg: 'rgba(255,143,31,0.07)'   },
  medium:   { hex: '#39ff14', rgb: '57,255,20',  bg: 'rgba(57,255,20,0.08)'  },
  low:      { hex: '#39ff14', rgb: '57,255,20',    bg: 'rgba(57,255,20,0.06)'    },
  default:  { hex: '#ff2bd6', rgb: '255,43,214',   bg: 'rgba(255,43,214,0.06)'   },
};

const sevNeon = (level) => {
  const normalized = String(level || '').trim().toLowerCase();
  return SEVERITY_NEON[normalized] || SEVERITY_NEON.default;
};

const ThreatCard = ({ threat }) => {
  const n = sevNeon(threat.severity);
  const severityLabel = String(threat.severity || '').trim().toUpperCase();

  return (
    <div style={{
      padding: '0.85rem 1rem',
      background: n.bg,
      borderLeft: `3px solid ${n.hex}`,
      boxShadow: `-4px 0 16px rgba(${n.rgb},0.4), inset 0 0 14px rgba(${n.rgb},0.04)`,
      marginBottom: 2,
    }}>
      <div className="flex items-start justify-between mb-2">
        <div style={{ fontFamily: "'Orbitron', monospace", fontSize: 12, fontWeight: 700, color: n.hex, letterSpacing: '0.06em', textTransform: 'uppercase', textShadow: `0 0 8px rgba(${n.rgb},0.55)` }}>{threat.name}</div>
        <Badge variant="outline" style={{ color: n.hex, borderColor: n.hex + '80', fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}>
          {severityLabel || 'UNKNOWN'}
        </Badge>
      </div>
      <p style={{ fontSize: 11, color: `rgba(${n.rgb},0.82)`, fontFamily: "'JetBrains Mono', monospace", marginBottom: 6 }}>{threat.type} · {threat.source_ip || 'Unknown source'}</p>
      <div className="flex items-center justify-between">
        <span style={{ fontSize: 11, padding: '2px 8px', background: `rgba(${n.rgb},0.12)`, border: `1px solid rgba(${n.rgb},0.4)`, color: n.hex, fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.08em' }}>
          {threat.status?.toUpperCase()}
        </span>
        <span style={{ fontSize: 11, color: '#5a8a9f', fontFamily: "'JetBrains Mono', monospace" }}>
          {new Date(threat.created_at).toLocaleTimeString()}
        </span>
      </div>
    </div>
  );
};

const AlertItem = ({ alert }) => {
  const n = sevNeon(alert.severity);
  const isNew = alert.status === 'new';

  return (
    <div className="flex items-start gap-3 p-3 transition-colors" style={{ borderBottom: '1px solid rgba(255,43,214,0.08)' }}>
      <div style={{
        width: 8, height: 8, borderRadius: '50%', marginTop: 6, flexShrink: 0,
        background: n.hex,
        boxShadow: `0 0 8px ${n.hex}, 0 0 16px rgba(${n.rgb},0.4)`,
        animation: isNew ? 'seraph-pulse-neon 1.8s ease-in-out infinite' : 'none',
      }} />
      <div className="flex-1 min-w-0">
        <p style={{ fontSize: 13, color: '#d7faff', fontFamily: "'Orbitron', monospace", fontWeight: 700, letterSpacing: '0.04em', marginBottom: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{alert.title}</p>
        <p style={{ fontSize: 11, color: '#7ecde0', fontFamily: "'JetBrains Mono', monospace", overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{alert.message}</p>
        <p style={{ fontSize: 10, color: '#4a7a8a', fontFamily: "'JetBrains Mono', monospace", marginTop: 3 }}>{new Date(alert.created_at).toLocaleString()}</p>
      </div>
      <Badge variant="outline" style={{ color: n.hex, borderColor: n.hex + '80', fontSize: 10, fontFamily: "'JetBrains Mono', monospace", flexShrink: 0 }}>
        {alert.type}
      </Badge>
    </div>
  );
};

const DashboardPage = () => {
  const navigate = useNavigate();
  const { getAuthHeaders } = useAuth();
  const [stats, setStats] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [timelineSource, setTimelineSource] = useState('unknown');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        // Fetch dashboard stats
        const [statsRes, timelineRes] = await Promise.all([
          axios.get(`${API}/dashboard/stats`, { headers: getAuthHeaders() }),
          axios.get(`${API}/dashboard/timeline`, { headers: getAuthHeaders() }),
        ]);

        setStats(statsRes.data);
        setTimeline(timelineRes.data.series || []);
        setTimelineSource(timelineRes.data.source || 'unknown');
      } catch (error) {
        toast.error('Failed to fetch dashboard data');
        console.error(error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, [getAuthHeaders]);

  const seedDemoData = async () => {
    try {
      await axios.post(`${API}/dashboard/seed`, {}, { headers: getAuthHeaders() });
      toast.success('Seeded demo threats/alerts (clearly marked demo)');
      setLoading(true);
      const [statsRes, timelineRes] = await Promise.all([
        axios.get(`${API}/dashboard/stats`, { headers: getAuthHeaders() }),
        axios.get(`${API}/dashboard/timeline`, { headers: getAuthHeaders() }),
      ]);
      setStats(statsRes.data);
      setTimeline(timelineRes.data.series || []);
      setTimelineSource(timelineRes.data.source || 'unknown');
    } catch (e) {
      toast.error('Failed to seed demo data');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="sophia-terminal-heading font-mono animate-pulse" style={{ color: '#ffb5f4' }}>Loading threat data...</div>
      </div>
    );
  }

  // Chart data
  const threatTypeData = Object.entries(stats?.threats_by_type || {}).map(([name, value]) => ({
    name: name.replace('_', ' ').toUpperCase(),
    value
  }));

  const severityData = Object.entries(stats?.threats_by_severity || {}).map(([name, value]) => ({
    name,
    value
  }));

  const COLORS = ['#00f6ff', '#ff35f4', '#39ff14', '#00f6ff'];

  const simulated = !timeline || timeline.length === 0;
  const timeSeriesData = simulated
    ? Array.from({ length: 24 }, (_, i) => ({
        time: `${String(i).padStart(2, '0')}:00`,
        threats: 0,
        blocked: 0,
      }))
    : timeline;

  return (
    <div className="p-6 lg:p-8 space-y-6 relative sophia-isolated" data-testid="dashboard-page" data-accent="orange">
      <SeraphPageHeader
        eyebrow="seraph · command · deck"
        title="Threat Dashboard"
        tagline="> real-time security monitoring & threat intelligence"
        accent="orange"
        status="LIVE"
        actions={
          <Button
            className="seraph-btn"
            onClick={() => window.location.reload()}
            data-testid="refresh-dashboard-btn"
            style={{ borderRadius: 0, padding: '0.65rem 1.1rem' }}
          >
            <Activity className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        }
      />

      {stats?.total_threats === 0 && (
        <div className="p-4 rounded text-sm flex items-center justify-between gap-4" style={dashboardPanelStyle(DASHBOARD_PANEL_ACCENTS.gold)}>
          <div>
            <span className="sophia-terminal-meta">No threats/alerts have been recorded yet. For a UI walkthrough, you can seed demo data (clearly labeled as demo).</span>
          </div>
          <Button onClick={seedDemoData} className="seraph-btn-primary">
            Seed Demo Data
          </Button>
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          index={0}
          icon={AlertTriangle}
          label="Active Threats"
          value={stats?.active_threats || 0}
          subValue={`${stats?.total_threats || 0} total detected`}
          color="red"
          glow={stats?.active_threats > 0}
        />
        <StatCard
          index={1}
          icon={Shield}
          label="Contained"
          value={stats?.contained_threats || 0}
          subValue="Awaiting resolution"
          color="amber"
        />
        <StatCard
          index={2}
          icon={Target}
          label="Resolved"
          value={stats?.resolved_threats || 0}
          subValue="Threats eliminated"
          color="green"
        />
        <StatCard
          index={3}
          icon={Cpu}
          label="AI Scans Today"
          value={stats?.ai_scans_today || 0}
          subValue="Behavioral analyses"
          color="blue"
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Activity Chart */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="lg:col-span-2 p-5"
          style={dashboardPanelStyle(DASHBOARD_PANEL_ACCENTS.magenta)}
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="sophia-terminal-heading" style={{ color: '#ffd1f8', textShadow: '0 0 10px rgba(255,43,214,0.34)' }}>Threat Activity</h3>
              <p className="sophia-terminal-meta text-xs" style={{ color: '#aaffe8' }}>
                24-hour threat detection timeline{' '}
                <span className="sophia-terminal-meta" style={{ color: '#ffcfb2' }}>
                  ({simulated ? 'no data yet' : timelineSource})
                </span>
              </p>
            </div>
            <div className="flex items-center gap-4 text-xs">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded bg-red-500" />
                <span className="text-slate-400" style={{ color: '#ff8d7c' }}>Detected</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded bg-green-500" />
                <span className="text-slate-400" style={{ color: '#8bffb4' }}>Blocked</span>
              </div>
            </div>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeSeriesData}>
                <defs>
                  <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ff3b30" stopOpacity={0.58} />
                    <stop offset="55%" stopColor="#ff3b30" stopOpacity={0.22} />
                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#39ff9f" stopOpacity={0.56} />
                    <stop offset="55%" stopColor="#39ff9f" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#10B981" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis 
                  dataKey="time" 
                  axisLine={false} 
                  tickLine={false}
                  tick={{ fill: '#bfefff', fontSize: 10 }}
                  interval={3}
                />
                <YAxis 
                  axisLine={false} 
                  tickLine={false}
                  tick={{ fill: '#bfefff', fontSize: 10 }}
                />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#071325', 
                    border: '1px solid rgba(255,43,214,0.32)',
                    borderRadius: '4px'
                  }}
                  labelStyle={{ color: '#ffd1f8' }}
                />
                <Area 
                  type="monotone" 
                  dataKey="threats" 
                  stroke="#ff3b30"
                  strokeWidth={2.2}
                  fillOpacity={1} 
                  fill="url(#threatGrad)" 
                />
                <Area 
                  type="monotone" 
                  dataKey="blocked" 
                  stroke="#39ff9f"
                  strokeWidth={2.2}
                  fillOpacity={1} 
                  fill="url(#blockedGrad)" 
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </motion.div>

        {/* Threat Distribution */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="p-5"
          style={dashboardPanelStyle(DASHBOARD_PANEL_ACCENTS.gold)}
        >
          <div className="mb-4">
            <h3 className="sophia-terminal-heading" style={{ color: DASHBOARD_PANEL_ACCENTS.gold.title }}>Threat Distribution</h3>
            <p className="sophia-terminal-meta text-xs" style={{ color: DASHBOARD_PANEL_ACCENTS.gold.meta }}>By severity level</p>
          </div>
          <div className="h-48 flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={70}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#0F172A', 
                    border: '1px solid rgba(57,255,20,0.42)',
                    borderRadius: '4px'
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-2 mt-4">
            {severityData.map((item, i) => (
              <div key={item.name} className="flex items-center gap-2">
                <div className="w-3 h-3 rounded" style={{ backgroundColor: COLORS[i] }} />
                <span className="sophia-terminal-meta text-xs capitalize">{item.name}</span>
                <span className="sophia-flicker sophia-terminal-value text-xs ml-auto" style={{ fontSize: '0.78rem', color: '#fff3d6' }}>{item.value}</span>
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* Bottom Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Threats */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          style={dashboardPanelStyle(DASHBOARD_PANEL_ACCENTS.rose || DASHBOARD_PANEL_ACCENTS.magenta)}
        >
          <div className="p-5 flex items-center justify-between" style={{ borderBottom: '1px solid rgba(255,43,214,0.16)' }}>
            <div>
              <h3 className="sophia-terminal-heading" style={{ color: '#ffd1f8' }}>Recent Threats</h3>
              <p className="sophia-terminal-meta text-xs">Latest detected threats</p>
            </div>
            <Button
              variant="ghost"
              size="sm"
              className="sophia-terminal-meta hover:text-white"
              onClick={() => navigate('/threats')}
            >
              View All <ChevronRight className="w-4 h-4 ml-1" />
            </Button>
          </div>
          <ScrollArea className="h-80">
            <div className="p-4 space-y-3">
              {stats?.recent_threats?.length > 0 ? (
                stats.recent_threats.map((threat) => (
                  <ThreatCard key={threat.id} threat={threat} />
                ))
              ) : (
                <div className="text-center py-8 sophia-terminal-meta">
                  <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p className="text-sm">No threats detected</p>
                </div>
              )}
            </div>
          </ScrollArea>
        </motion.div>

        {/* Recent Alerts */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          style={dashboardPanelStyle(DASHBOARD_PANEL_ACCENTS.cyan)}
        >
          <div className="p-5 flex items-center justify-between" style={{ borderBottom: '1px solid rgba(0,240,255,0.14)' }}>
            <div className="flex items-center gap-3">
              <h3 className="sophia-terminal-heading" style={{ color: '#dff8ff' }}>Alert Feed</h3>
              {stats?.critical_alerts > 0 && (
                <Badge
                  style={{
                    background: 'rgba(255,59,48,0.18)',
                    color: '#ff7a66',
                    border: '1px solid rgba(255,59,48,0.42)',
                  }}
                >
                  {stats.critical_alerts} Critical
                </Badge>
              )}
            </div>
            <Button
              variant="ghost"
              size="sm"
              className="sophia-terminal-meta hover:text-white"
              onClick={() => navigate('/alerts')}
            >
              View All <ChevronRight className="w-4 h-4 ml-1" />
            </Button>
          </div>
          <ScrollArea className="h-80">
            <div className="divide-y divide-slate-800">
              {stats?.recent_alerts?.length > 0 ? (
                stats.recent_alerts.map((alert) => (
                  <AlertItem key={alert.id} alert={alert} />
                ))
              ) : (
                <div className="text-center py-8 sophia-terminal-meta">
                  <Zap className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p className="text-sm">No alerts</p>
                </div>
              )}
            </div>
          </ScrollArea>
        </motion.div>
      </div>

      {/* System Health Bar */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="p-5"
        style={dashboardPanelStyle(DASHBOARD_PANEL_ACCENTS.green)}
      >
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-3">
            <Activity className="w-5 h-5 text-green-400" />
            <h3 className="sophia-terminal-heading" style={{ color: DASHBOARD_PANEL_ACCENTS.green.title }}>System Health</h3>
          </div>
          <span className="sophia-flicker sophia-terminal-value text-2xl font-bold" style={{ color: '#8bffb4' }}>
            {stats?.system_health?.toFixed(1) || 100}%
          </span>
        </div>
        <div className="h-3 bg-slate-800 rounded-full overflow-hidden">
          <div 
            className="h-full bg-gradient-to-r from-green-500 to-emerald-400 transition-all duration-500"
            style={{ width: `${stats?.system_health || 100}%` }}
          />
        </div>
        <div className="flex items-center justify-between mt-3 text-xs sophia-terminal-meta">
          <span>Defense modules operational</span>
          <span>Last updated: {new Date().toLocaleTimeString()}</span>
        </div>
      </motion.div>
    </div>
  );
};

export default DashboardPage;
