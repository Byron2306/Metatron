import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion, AnimatePresence } from 'framer-motion';
import SeraphPageHeader from '../components/SeraphPageHeader';
import { 
  Shield, AlertTriangle, CheckCircle, XCircle, Clock,
  Activity, Terminal, Zap, Eye, Lock, RefreshCw,
  ChevronRight, Play, Pause, Target, Radio, Cpu,
  Network, Server, AlertOctagon, ShieldAlert, Ban
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../components/ui/tabs';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const NEON_STAT_STYLES = {
  cyan: {
    border: 'rgba(255,242,0,0.72)',
    iconBg: 'rgba(255,242,0,0.16)',
    icon: '#00f6ff',
    value: '#fff200',
    glow: 'rgba(255,242,0,0.26)',
  },
  pink: {
    border: 'rgba(255,23,77,0.72)',
    iconBg: 'rgba(255,23,77,0.16)',
    icon: '#ff174d',
    value: '#ff174d',
    glow: 'rgba(255,23,77,0.26)',
  },
  purple: {
    border: 'rgba(255,23,77,0.7)',
    iconBg: 'rgba(255,23,77,0.15)',
    icon: '#ff174d',
    value: '#ff174d',
    glow: 'rgba(255,23,77,0.24)',
  },
  green: {
    border: 'rgba(57,255,20,0.4)',
    iconBg: 'rgba(57,255,20,0.12)',
    icon: '#96ff97',
    value: '#96ff97',
    glow: 'rgba(57,255,20,0.2)',
  },
};

const COMMAND_PANEL_STYLE = (accent, shadow = 'rgba(0,240,255,0.12)') => ({
  background: 'linear-gradient(155deg, rgba(8,20,38,0.94), rgba(3,9,18,0.97))',
  border: `3px solid ${accent}`,
  boxShadow: `0 0 8px ${shadow}, 0 0 18px ${shadow}, inset 0 0 14px ${shadow.replace('0.28', '0.08').replace('0.42', '0.08')}`,
  clipPath: 'polygon(10px 0, 100% 0, 100% calc(100% - 10px), calc(100% - 10px) 100%, 0 100%, 0 10px)',
});

const COMMAND_TAB_STYLE = {
  approvals: { accent: '#fff200', text: '#fff200', glow: 'rgba(255,242,0,0.28)' },
  threats: { accent: '#ff174d', text: '#ff174d', glow: 'rgba(255,23,77,0.3)' },
  agents: { accent: '#39ff14', text: '#39ff14', glow: 'rgba(57,255,20,0.42)' },
  history: { accent: '#ff8a00', text: '#ff8a00', glow: 'rgba(255,138,0,0.28)' },
};

const CommandCenterPage = () => {
  const { token } = useAuth();
  const [pendingCommands, setPendingCommands] = useState([]);
  const [recentCommands, setRecentCommands] = useState([]);
  const [threats, setThreats] = useState([]);
  const [agents, setAgents] = useState([]);
  const [stats, setStats] = useState({});
  const [commandStats, setCommandStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [actionInProgress, setActionInProgress] = useState({});

  const headers = { Authorization: `Bearer ${token}` };

  const fetchData = useCallback(async () => {
    try {
      const req = { headers, timeout: 8000 };
      const results = await Promise.allSettled([
        axios.get(`${API}/agent-commands/pending`, req),
        axios.get(`${API}/agent-commands/history?limit=20`, req),
        axios.get(`${API}/agent-commands/stats`, req),
        axios.get(`${API}/swarm/overview`, req),
        axios.get(`${API}/dashboard/stats`, req),
        axios.get(`${API}/threats?severity=critical`, req),
        axios.get(`${API}/threats?severity=high`, req),
        axios.get(`${API}/agent-commands/agents/status`, req),
      ]);

      const [
        pendingRes,
        historyRes,
        commandStatsRes,
        agentsRes,
        dashboardRes,
        criticalThreatsRes,
        highThreatsRes,
        connectedRes,
      ] = results.map((r) =>
        r.status === 'fulfilled' ? r.value : null
      );

      if (pendingRes?.data) setPendingCommands(pendingRes.data.commands || []);
      if (historyRes?.data) setRecentCommands(historyRes.data.commands || []);
      if (commandStatsRes?.data) setCommandStats(commandStatsRes.data);
      if (agentsRes?.data) setStats(agentsRes.data || {});

      const dashboardStats = dashboardRes?.data || {};
      const threatsMerged = [
        ...(criticalThreatsRes?.data || []),
        ...(highThreatsRes?.data || []),
      ];
      // De-dup by id.
      const seen = new Set();
      const threatsDedup = threatsMerged.filter((t) => {
        const id = t?.id;
        if (!id || seen.has(id)) return false;
        seen.add(id);
        return true;
      });
      // Provide both "threat response" items and the headline counts.
      setThreats(threatsDedup);
      setStats((prev) => ({
        ...prev,
        dashboard: dashboardStats,
      }));

      if (connectedRes?.data) setAgents(connectedRes.data.agents || []);

      // If any core call failed, surface a soft warning but keep the UI responsive.
      if (results.some((r) => r.status === 'rejected')) {
        console.warn('One or more Command Center requests failed', results);
      }
    } catch (err) {
      console.error('Failed to fetch command center data:', err);
    } finally {
      setLoading(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  useEffect(() => {
    fetchData();
    // Refresh every 60s — the previous 5s interval was making the threat list
    // and pending-commands queue snap back to the top constantly while the
    // operator was reading them.
    const interval = setInterval(fetchData, 60000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const approveCommand = async (commandId, approved) => {
    setActionInProgress(prev => ({ ...prev, [commandId]: true }));
    try {
      await axios.post(`${API}/agent-commands/${commandId}/approve`, 
        { approved, notes: '' },
        { headers }
      );
      toast.success(approved ? 'Command approved and sent to agent' : 'Command rejected');
      fetchData();
    } catch (err) {
      toast.error('Failed to process command');
    } finally {
      setActionInProgress(prev => ({ ...prev, [commandId]: false }));
    }
  };

  const sendQuickCommand = async (agentId, commandType, params) => {
    try {
      await axios.post(`${API}/agent-commands/create`, {
        agent_id: agentId,
        command_type: commandType,
        parameters: params,
        priority: 'high'
      }, { headers });
      toast.success('Command queued for approval');
      fetchData();
    } catch (err) {
      toast.error('Failed to create command');
    }
  };

  const respondToThreat = async (threat, action) => {
    const agentId = threat.host_id || threat.agent_id;
    if (!agentId) {
      toast.error('No agent associated with this threat');
      return;
    }

    let commandType = '';
    let params = {};

    switch (action) {
      case 'kill_process':
        commandType = 'kill_process';
        params = { pid: threat.data?.pid, process_name: threat.data?.name };
        break;
      case 'block_ip':
        commandType = 'block_ip';
        params = { ip_address: threat.data?.remote_ip || threat.data?.ip };
        break;
      case 'quarantine':
        commandType = 'quarantine_file';
        params = { file_path: threat.data?.filepath };
        break;
      case 'isolate':
        commandType = 'block_ip';
        params = { ip_address: '0.0.0.0', duration_hours: 24 }; // Network isolation
        break;
      default:
        return;
    }

    await sendQuickCommand(agentId, commandType, params);
  };

  const getSeverityStyle = (severity) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/50';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/50';
      case 'medium': return 'bg-green-500/20 text-green-400 border-green-500/50';
      case 'low': return 'bg-green-500/18 text-green-300 border-green-500/40';
      default: return 'bg-slate-500/20 text-slate-400 border-slate-500/50';
    }
  };

  const getRiskStyle = (level) => {
    switch (level) {
      case 'critical': return 'bg-red-600';
      case 'high': return 'bg-orange-600';
      case 'medium': return 'bg-green-600';
      case 'low': return 'bg-green-600';
      default: return 'bg-slate-600';
    }
  };

  const getStatusStyle = (status) => {
    switch (status) {
      case 'pending_approval': return 'bg-cyan-500/20 text-cyan-300';
      case 'approved': case 'sent_to_agent': return 'bg-fuchsia-500/18 text-fuchsia-300';
      case 'completed': return 'bg-green-500/20 text-green-400';
      case 'failed': case 'rejected': return 'bg-red-500/20 text-red-400';
      default: return 'bg-slate-500/20 text-slate-400';
    }
  };

  const getSeverityTextHex = (level) => {
    switch (String(level || '').toLowerCase()) {
      case 'critical':
        return '#ff174d';
      case 'high':
        return '#ff174d';
      case 'medium':
        return '#fff200';
      case 'low':
        return '#39ff14';
      default:
        return '#fff200';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2" style={{ borderColor: '#00f6ff' }}></div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6 lg:p-8 sophia-isolated" data-testid="command-center-page">
      <SeraphPageHeader
        eyebrow="seraph · command · agent fleet"
        title={<span className="seraph-heading-flood-rtl">Command Center</span>}
        tagline="> threat response · agent control · governed dispatch"
        accent="gold"
        status={pendingCommands.length > 0 ? `${pendingCommands.length} PENDING` : 'OPERATIONAL'}
        actions={
          <Button
            onClick={fetchData}
            variant="outline"
            style={{
              background: 'rgba(0,240,255,0.2)',
              borderColor: 'rgba(0,240,255,0.82)',
              color: '#00f6ff',
              boxShadow: '0 0 10px rgba(0,240,255,0.38), inset 0 0 12px rgba(0,240,255,0.18)',
            }}
          >
            <RefreshCw className="w-4 h-4 mr-2" style={{ color: '#00f6ff' }} />
            Refresh
          </Button>
        }
      />

      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card
          style={{
            background: 'linear-gradient(155deg, rgba(10,24,44,0.95), rgba(4,11,22,0.96))',
            border: `3px solid ${NEON_STAT_STYLES.cyan.border}`,
            boxShadow: `0 0 18px ${NEON_STAT_STYLES.cyan.glow}`,
            clipPath: 'polygon(10px 0, 100% 0, 100% calc(100% - 10px), calc(100% - 10px) 100%, 0 100%, 0 10px)',
          }}
        >
          <CardContent className="p-4 flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ backgroundColor: NEON_STAT_STYLES.cyan.iconBg, border: `1px solid ${NEON_STAT_STYLES.cyan.border}` }}>
              <Radio className="w-6 h-6" style={{ color: NEON_STAT_STYLES.cyan.icon }} />
            </div>
            <div>
              <p className="sophia-flicker sophia-terminal-value text-3xl font-bold" style={{ color: NEON_STAT_STYLES.cyan.value, textShadow: `0 0 10px ${NEON_STAT_STYLES.cyan.glow}` }}>{stats.agents?.online || 0}</p>
              <p className="sophia-scan sophia-terminal-label text-sm">Agents Online</p>
            </div>
          </CardContent>
        </Card>

        <Card
          style={{
            background: 'linear-gradient(155deg, rgba(10,24,44,0.95), rgba(4,11,22,0.96))',
            border: `3px solid ${NEON_STAT_STYLES.pink.border}`,
            boxShadow: `0 0 18px ${NEON_STAT_STYLES.pink.glow}`,
            clipPath: 'polygon(10px 0, 100% 0, 100% calc(100% - 10px), calc(100% - 10px) 100%, 0 100%, 0 10px)',
          }}
        >
          <CardContent className="p-4 flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ backgroundColor: NEON_STAT_STYLES.pink.iconBg, border: `1px solid ${NEON_STAT_STYLES.pink.border}` }}>
              <AlertTriangle className="w-6 h-6" style={{ color: NEON_STAT_STYLES.pink.icon }} />
            </div>
            <div>
              <p className="sophia-flicker sophia-terminal-value text-3xl font-bold" style={{ color: NEON_STAT_STYLES.pink.value, textShadow: `0 0 10px ${NEON_STAT_STYLES.pink.glow}` }}>{pendingCommands.length}</p>
              <p className="sophia-scan sophia-terminal-label text-sm">Pending Commands</p>
            </div>
          </CardContent>
        </Card>

        <Card
          style={{
            background: 'linear-gradient(155deg, rgba(10,24,44,0.95), rgba(4,11,22,0.96))',
            border: `3px solid ${NEON_STAT_STYLES.purple.border}`,
            boxShadow: `0 0 18px ${NEON_STAT_STYLES.purple.glow}`,
            clipPath: 'polygon(10px 0, 100% 0, 100% calc(100% - 10px), calc(100% - 10px) 100%, 0 100%, 0 10px)',
          }}
        >
          <CardContent className="p-4 flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ backgroundColor: NEON_STAT_STYLES.purple.iconBg, border: `1px solid ${NEON_STAT_STYLES.purple.border}` }}>
              <Activity className="w-6 h-6" style={{ color: NEON_STAT_STYLES.purple.icon }} />
            </div>
            <div>
              <p className="sophia-flicker sophia-terminal-value text-3xl font-bold" style={{ color: NEON_STAT_STYLES.purple.value, textShadow: `0 0 10px ${NEON_STAT_STYLES.purple.glow}` }}>{threats.length}</p>
              <p className="sophia-scan sophia-terminal-label text-sm">Active Threats</p>
            </div>
          </CardContent>
        </Card>

        <Card
          style={{
            background: 'linear-gradient(155deg, rgba(10,24,44,0.95), rgba(4,11,22,0.96))',
            border: `3px solid ${NEON_STAT_STYLES.green.border}`,
            boxShadow: `0 0 18px ${NEON_STAT_STYLES.green.glow}`,
            clipPath: 'polygon(10px 0, 100% 0, 100% calc(100% - 10px), calc(100% - 10px) 100%, 0 100%, 0 10px)',
          }}
        >
          <CardContent className="p-4 flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ backgroundColor: NEON_STAT_STYLES.green.iconBg, border: `1px solid ${NEON_STAT_STYLES.green.border}` }}>
              <CheckCircle className="w-6 h-6" style={{ color: NEON_STAT_STYLES.green.icon }} />
            </div>
            <div>
              <p className="sophia-flicker sophia-terminal-value text-3xl font-bold" style={{ color: NEON_STAT_STYLES.green.value, textShadow: `0 0 10px ${NEON_STAT_STYLES.green.glow}` }}>
                {commandStats?.executed ?? recentCommands.filter(c => c.status === 'completed').length}
              </p>
              <p className="sophia-scan sophia-terminal-label text-sm">Commands Executed</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <Tabs defaultValue="approvals" className="w-full">
        <TabsList
          className="mb-4"
          style={{
            ...COMMAND_PANEL_STYLE('rgba(0,240,255,0.72)', 'rgba(0,240,255,0.28)'),
            padding: '0.35rem',
            gap: '0.35rem',
          }}
        >
          <TabsTrigger value="approvals" className="data-[state=active]:text-white" style={{ color: '#c7ddea', letterSpacing: '0.14em', textTransform: 'uppercase', fontFamily: "'FfMoon', 'Orbitron', sans-serif", border: `1px solid ${COMMAND_TAB_STYLE.approvals.accent}26`, background: 'rgba(8,20,38,0.62)' }}>
            <Clock className="w-4 h-4 mr-2" />
            Pending Approvals ({pendingCommands.length})
          </TabsTrigger>
          <TabsTrigger value="threats" className="data-[state=active]:text-white" style={{ color: '#c7ddea', letterSpacing: '0.14em', textTransform: 'uppercase', fontFamily: "'FfMoon', 'Orbitron', sans-serif", border: `1px solid ${COMMAND_TAB_STYLE.threats.accent}26`, background: 'rgba(8,20,38,0.62)' }}>
            <AlertTriangle className="w-4 h-4 mr-2" />
            Active Threats ({threats.length})
          </TabsTrigger>
          <TabsTrigger value="agents" className="data-[state=active]:text-white" style={{ color: '#c7ddea', letterSpacing: '0.14em', textTransform: 'uppercase', fontFamily: "'FfMoon', 'Orbitron', sans-serif", border: `1px solid ${COMMAND_TAB_STYLE.agents.accent}26`, background: 'rgba(8,20,38,0.62)' }}>
            <Server className="w-4 h-4 mr-2" />
            Agent Control
          </TabsTrigger>
          <TabsTrigger value="history" className="data-[state=active]:text-white" style={{ color: '#c7ddea', letterSpacing: '0.14em', textTransform: 'uppercase', fontFamily: "'FfMoon', 'Orbitron', sans-serif", border: `1px solid ${COMMAND_TAB_STYLE.history.accent}26`, background: 'rgba(8,20,38,0.62)' }}>
            <Terminal className="w-4 h-4 mr-2" />
            Command History
          </TabsTrigger>
        </TabsList>

        {/* Pending Approvals Tab */}
        <TabsContent value="approvals" className="mt-4">
          {pendingCommands.length === 0 ? (
            <div style={{
              background: 'linear-gradient(160deg, rgba(2,14,8,0.9), rgba(2,8,19,0.95))',
              border: '1px solid rgba(57,255,20,0.35)',
              boxShadow: '0 0 24px rgba(57,255,20,0.12), inset 0 0 20px rgba(57,255,20,0.04)',
              clipPath: 'polygon(12px 0, 100% 0, 100% calc(100% - 12px), calc(100% - 12px) 100%, 0 100%, 0 12px)',
              padding: '2rem',
              textAlign: 'center'
            }}>
              <CheckCircle className="w-14 h-14 mx-auto mb-4" style={{ color: '#39ff14', filter: 'drop-shadow(0 0 10px rgba(57,255,20,0.7))' }} />
              <p className="sophia-terminal-heading" style={{ color: '#7fffa6' }}>All Clear</p>
              <p className="sophia-terminal-meta" style={{ fontSize: '0.8rem', marginTop: '0.25rem' }}>No commands pending approval</p>
            </div>
          ) : (
            // Pending-approval cards now mirror the ThreatCard pattern in
            // ThreatsPage so the operator sees a consistent grammar across
            // alerts / threats / pending. Severity-tinted header strip,
            // pills, footer with timestamp + action buttons.
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {pendingCommands.map((cmd) => {
                const sevPalette = {
                  critical: { border: 'border-red-500', text: 'text-red-400', bg: 'bg-red-500/10', glow: 'rgba(255,23,77,0.32)', textHex: '#ff174d' },
                  high:     { border: 'border-red-500', text: 'text-red-400', bg: 'bg-red-500/10', glow: 'rgba(255,23,77,0.3)', textHex: '#ff174d' },
                  medium:   { border: 'border-yellow-500', text: 'text-yellow-400', bg: 'bg-yellow-500/10', glow: 'rgba(255,242,0,0.28)', textHex: '#fff200' },
                  low:      { border: 'border-green-500', text: 'text-green-400', bg: 'bg-green-500/10', glow: 'rgba(57,255,20,0.5)', textHex: '#a8ffac' },
                };
                const sev = sevPalette[cmd.risk_level] || sevPalette.medium;
                return (
                  <motion.div
                    key={cmd.command_id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className={`bg-slate-900/50 backdrop-blur-md border ${sev.border}/40 rounded overflow-hidden transition-all duration-300`}
                    style={{ boxShadow: `0 0 0 1px ${sev.glow.replace('0.55','0.2').replace('0.5','0.18').replace('0.45','0.16')}` }}
                  >
                    {/* Header strip — severity-tinted, mirrors ThreatCard */}
                    <div className={`p-4 ${sev.bg} border-b border-slate-800`}>
                      <div className="flex items-start justify-between">
                        <div className="flex items-start gap-3">
                          <div className={`w-10 h-10 rounded ${sev.bg} flex items-center justify-center`} style={{ color: sev.textHex }}>
                            <Zap className="w-5 h-5" style={{ filter: `drop-shadow(0 0 6px ${sev.glow})` }} />
                          </div>
                          <div>
                            <div className="sophia-flicker sophia-terminal-value text-base" style={{ fontSize: '1rem', color: '#e6fbff' }}>{cmd.command_name || cmd.command_type}</div>
                            <div className="flex items-center gap-2 mt-1 flex-wrap">
                              <Badge variant="outline" className={`${sev.border}/50 text-xs`} style={{ color: sev.textHex }}>
                                {cmd.risk_level || 'medium'} risk
                              </Badge>
                              <Badge variant="outline" className="text-slate-400 border-slate-600 text-xs">
                                {(cmd.command_type || '').replace(/_/g, ' ')}
                              </Badge>
                              {cmd.priority ? (
                                <Badge variant="outline" className="text-cyan-300 border-cyan-700 text-xs">
                                  {cmd.priority}
                                </Badge>
                              ) : null}
                            </div>
                          </div>
                        </div>
                        <span className="text-xs px-2 py-1 rounded bg-cyan-500/20 text-cyan-300">
                          pending
                        </span>
                      </div>
                    </div>

                    {/* Body */}
                    <div className="p-4 space-y-3">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                        <div className="flex items-center gap-2">
                          <Server className="w-4 h-4 text-slate-500" />
                            <span className="sophia-terminal-meta">
                              Agent:{' '}
                              <span className="sophia-flicker sophia-terminal-value text-sm" style={{ fontSize: '0.84rem', color: '#ffffff' }}>
                              {cmd.agent_id ? cmd.agent_id.slice(0, 16) + (cmd.agent_id.length > 16 ? '…' : '') : '—'}
                            </span>
                          </span>
                        </div>
                        {cmd.created_by ? (
                          <div className="flex items-center gap-2">
                            <Eye className="w-4 h-4 text-slate-500" />
                            <span className="sophia-terminal-meta">
                              By: <span className="sophia-flicker sophia-terminal-value text-sm" style={{ fontSize: '0.84rem', color: '#ffffff' }}>{cmd.created_by}</span>
                            </span>
                          </div>
                        ) : null}
                      </div>

                      {cmd.parameters && Object.keys(cmd.parameters).length ? (
                        <details className="rounded border border-cyan-500/20 bg-slate-950/50">
                          <summary className="px-3 py-2 cursor-pointer sophia-terminal-label text-xs select-none">
                            Parameters ({Object.keys(cmd.parameters).length})
                          </summary>
                          <pre className="px-3 pb-3 text-xs font-mono text-cyan-100 overflow-x-auto">
                            {JSON.stringify(cmd.parameters, null, 2)}
                          </pre>
                        </details>
                      ) : null}
                    </div>

                    {/* Footer — timestamp + Approve/Reject buttons */}
                    <div className="p-4 border-t border-slate-800 flex items-center justify-between gap-3 flex-wrap">
                      <div className="flex items-center gap-2 text-xs text-slate-500">
                        <Clock className="w-3 h-3" />
                        {cmd.created_at ? new Date(cmd.created_at).toLocaleString() : '—'}
                      </div>
                      <div className="flex items-center gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-xs border-red-700 text-red-400 hover:bg-red-500/10"
                          onClick={() => approveCommand(cmd.command_id, false)}
                          disabled={actionInProgress[cmd.command_id]}
                        >
                          <XCircle className="w-3 h-3 mr-1" />
                          Reject
                        </Button>
                        <Button
                          size="sm"
                          className="text-xs bg-green-600 hover:bg-green-700 text-white"
                          onClick={() => approveCommand(cmd.command_id, true)}
                          disabled={actionInProgress[cmd.command_id]}
                        >
                          {actionInProgress[cmd.command_id] ? (
                            <RefreshCw className="w-3 h-3 mr-1 animate-spin" />
                          ) : (
                            <CheckCircle className="w-3 h-3 mr-1" />
                          )}
                          Approve
                        </Button>
                      </div>
                    </div>
                  </motion.div>
              );})}
            </div>
          )}
        </TabsContent>

        {/* Active Threats Tab */}
        <TabsContent value="threats" className="mt-4">
          {threats.length === 0 ? (
            <Card
              style={{
                background: 'linear-gradient(155deg, rgba(8,22,18,0.94), rgba(4,11,20,0.96))',
                border: '1px solid rgba(57,255,20,0.42)',
                boxShadow: '0 0 22px rgba(57,255,20,0.18), inset 0 0 16px rgba(57,255,20,0.06)',
              }}
            >
              <CardContent className="p-8 text-center">
                <Shield className="w-16 h-16 mx-auto mb-4" style={{ color: '#96ff97', filter: 'drop-shadow(0 0 8px rgba(57,255,20,0.55))' }} />
                <h3 className="sophia-terminal-heading text-xl mb-2" style={{ color: '#c8ffd0' }}>System Secure</h3>
                <p className="sophia-terminal-meta">No critical threats detected</p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {threats.map((threat, idx) => {
                // Threats coming from /api/threats use name/description/source_ip/target_system/created_at.
                // Threats coming from /swarm/telemetry use event_type/host_id/data/timestamp.
                // Normalize so both render correctly.
                const title =
                  threat.name ||
                  threat.event_type ||
                  threat.type ||
                  threat.description?.split('\n')[0] ||
                  'Threat detected';
                const subtitle =
                  threat.description ||
                  threat.data?.message ||
                  (threat.data ? JSON.stringify(threat.data).slice(0, 140) : null);
                const host =
                  threat.target_system ||
                  threat.host_id ||
                  threat.data?.hostname ||
                  threat.data?.host ||
                  'Unknown';
                const sourceIp =
                  threat.source_ip || threat.data?.remote_ip || threat.data?.ip;
                const ts = threat.created_at || threat.timestamp || threat.first_seen;
                const indicators = Array.isArray(threat.indicators) ? threat.indicators : [];
                return (
                <motion.div
                  key={threat.id || idx}
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                    className="rounded-xl p-4 border-2"
                  style={{ ...COMMAND_PANEL_STYLE(`${getSeverityTextHex(threat.severity)}66`, 'rgba(0,0,0,0.08)'), backgroundColor: 'rgba(18, 24, 51, 0.88)' }}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <Badge className={getSeverityStyle(threat.severity)} style={{ color: getSeverityTextHex(threat.severity) }}>
                        {(threat.severity || 'unknown').toUpperCase()}
                      </Badge>
                      <div className="sophia-flicker sophia-terminal-value font-semibold mt-2" style={{ color: '#e6fbff', fontSize: '1rem' }}>{title}</div>
                      <p className="sophia-terminal-meta text-sm">Host: {host}{sourceIp ? ` · ${sourceIp}` : ''}</p>
                    </div>
                    <span className="sophia-terminal-meta text-xs">
                      {ts ? new Date(ts).toLocaleTimeString() : ''}
                    </span>
                  </div>

                  {subtitle && (
                    <div className="p-2 rounded mb-3" style={{ backgroundColor: 'rgba(0,0,0,0.3)' }}>
                      <p className="sophia-terminal-meta text-sm">{subtitle}</p>
                    </div>
                  )}

                  {indicators.length > 0 && (
                    <div className="flex flex-wrap gap-1 mb-3">
                      {indicators.slice(0, 6).map((ind, i) => (
                        <Badge
                          key={i}
                          variant="outline"
                          className="text-[10px]"
                          style={{
                            background: 'rgba(0,240,255,0.06)',
                            border: '1px solid rgba(0,240,255,0.32)',
                            color: '#aef0ff',
                            letterSpacing: '0.04em',
                          }}
                        >
                          {String(ind).slice(0, 32)}
                        </Badge>
                      ))}
                    </div>
                  )}

                  {/* Quick Response Actions */}
                  <div className="flex flex-wrap gap-2">
                    {threat.data?.pid && (
                      <Button
                        size="sm"
                        className="bg-red-600 hover:bg-red-700"
                        onClick={() => respondToThreat(threat, 'kill_process')}
                      >
                        <Ban className="w-3 h-3 mr-1" />
                        Kill Process
                      </Button>
                    )}
                    {sourceIp && (
                      <Button
                        size="sm"
                        className="bg-orange-600 hover:bg-orange-700"
                        onClick={() => respondToThreat(threat, 'block_ip')}
                      >
                        <Lock className="w-3 h-3 mr-1" />
                        Block IP
                      </Button>
                    )}
                    {threat.data?.filepath && (
                      <Button
                        size="sm"
                        className="bg-green-600 hover:bg-green-700"
                        onClick={() => respondToThreat(threat, 'quarantine')}
                      >
                        <Shield className="w-3 h-3 mr-1" />
                        Quarantine
                      </Button>
                    )}
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-slate-600"
                      style={{ borderColor: 'rgba(0,240,255,0.32)', color: '#d6fbff', boxShadow: '0 0 8px rgba(0,240,255,0.08)' }}
                      onClick={() => setSelectedThreat(threat)}
                    >
                      <Eye className="w-3 h-3 mr-1" />
                      Details
                    </Button>
                  </div>
                </motion.div>
                );
              })}
            </div>
          )}
        </TabsContent>

        {/* Agent Control Tab */}
        <TabsContent value="agents" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {agents.map((agent) => (
              <Card 
                key={agent.agent_id}
                style={{ 
                  background: 'linear-gradient(155deg, rgba(10,24,44,0.95), rgba(4,11,22,0.96))',
                  border: agent.connected ? '1px solid rgba(57,255,20,0.46)' : '1px solid rgba(140,174,190,0.34)',
                  boxShadow: agent.connected
                    ? '0 0 18px rgba(57,255,20,0.18), inset 0 0 12px rgba(57,255,20,0.04)'
                    : '0 0 14px rgba(0,240,255,0.1), inset 0 0 10px rgba(0,240,255,0.03)'
                }}
              >
                <CardContent className="p-4">
                  <div className="flex items-center gap-3 mb-4">
                    <div className={`w-3 h-3 rounded-full ${agent.connected ? 'bg-green-400 animate-pulse' : 'bg-slate-500'}`} />
                    <div>
                      <p className="sophia-flicker sophia-terminal-value font-medium" style={{ color: '#e6fbff', fontSize: '0.96rem' }}>{agent.hostname || agent.agent_id}</p>
                      <p className="sophia-terminal-meta text-xs">{agent.os} | {agent.ip_address}</p>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/10"
                      onClick={() => sendQuickCommand(agent.agent_id, 'full_scan', { scan_types: ['all'] })}
                    >
                      <Target className="w-3 h-3 mr-1" />
                      Scan
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-purple-500/50 text-purple-400 hover:bg-purple-500/10"
                      onClick={() => sendQuickCommand(agent.agent_id, 'collect_forensics', { collection_type: 'quick' })}
                    >
                      <Cpu className="w-3 h-3 mr-1" />
                      Forensics
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-fuchsia-500/50 text-fuchsia-300 hover:bg-fuchsia-500/10"
                      onClick={() => sendQuickCommand(agent.agent_id, 'restart_service', { service_name: 'seraph-defender' })}
                    >
                      <RefreshCw className="w-3 h-3 mr-1" />
                      Restart
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-green-500/50 text-green-400 hover:bg-green-500/10"
                      onClick={() => sendQuickCommand(agent.agent_id, 'update_agent', {})}
                    >
                      <Activity className="w-3 h-3 mr-1" />
                      Update
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
            
            {agents.length === 0 && (
              <Card
                style={{
                  background: 'linear-gradient(155deg, rgba(10,24,44,0.95), rgba(4,11,22,0.96))',
                  border: '1px solid rgba(0,240,255,0.34)',
                  boxShadow: '0 0 18px rgba(0,240,255,0.12)',
                }}
                className="col-span-full"
              >
                <CardContent className="p-8 text-center">
                  <Server className="w-16 h-16 mx-auto mb-4" style={{ color: '#8defff' }} />
                  <h3 className="text-xl font-semibold mb-2" style={{ color: '#dff8ff' }}>No Agents Registered</h3>
                  <p style={{ color: '#89bfd2' }}>Deploy Seraph Defender agents to your endpoints</p>
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>

        {/* Command History Tab */}
        <TabsContent value="history" className="mt-4">
          <Card
            style={{
              background: 'linear-gradient(155deg, rgba(10,24,44,0.95), rgba(4,11,22,0.96))',
              border: '1px solid rgba(0,240,255,0.36)',
              boxShadow: '0 0 22px rgba(0,240,255,0.14), inset 0 0 18px rgba(0,240,255,0.06)',
            }}
          >
            <CardHeader>
              <CardTitle className="sophia-terminal-heading" style={{ color: '#dff8ff', textShadow: '0 0 10px rgba(0,240,255,0.35)' }}>Recent Commands</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {recentCommands.map((cmd) => (
                  <div
                    key={cmd.command_id}
                    className="flex items-center justify-between p-3 rounded-lg"
                    style={{
                      background: 'linear-gradient(140deg, rgba(9,19,35,0.84), rgba(4,11,20,0.9))',
                      border: '1px solid rgba(0,240,255,0.22)',
                    }}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`w-2 h-2 rounded-full ${
                        cmd.status === 'completed' ? 'bg-green-400' :
                        cmd.status === 'failed' ? 'bg-red-400' :
                        cmd.status === 'pending_approval' ? 'bg-cyan-400' :
                        'bg-blue-400'
                      }`} />
                      <div>
                        <p className="sophia-flicker sophia-terminal-value text-sm font-medium" style={{ color: '#dff8ff', fontSize: '0.92rem' }}>{cmd.command_name}</p>
                        <p className="sophia-terminal-meta text-xs">
                          {cmd.agent_id} • {new Date(cmd.created_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <Badge className={getStatusStyle(cmd.status)}>
                      {cmd.status.replace('_', ' ')}
                    </Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Threat Detail Modal */}
      <AnimatePresence>
        {selectedThreat && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4"
            onClick={() => setSelectedThreat(null)}
          >
            <motion.div
              initial={{ scale: 0.9 }}
              animate={{ scale: 1 }}
              exit={{ scale: 0.9 }}
              className="max-w-2xl w-full rounded-xl p-6"
              style={{
                background: 'linear-gradient(160deg, rgba(8,20,38,0.96), rgba(4,11,22,0.98))',
                border: '2px solid rgba(0,240,255,0.4)',
                boxShadow: '0 0 28px rgba(0,240,255,0.2), inset 0 0 18px rgba(0,240,255,0.06)',
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <h2 className="sophia-terminal-heading text-xl mb-4" style={{ color: '#dff8ff', textShadow: '0 0 9px rgba(0,240,255,0.34)' }}>Threat Details</h2>
              <div className="space-y-4">
                <div>
                  <p className="sophia-scan sophia-terminal-label text-sm">Event Type</p>
                  <p className="sophia-flicker sophia-terminal-value" style={{ color: '#e6fbff' }}>{selectedThreat.event_type}</p>
                </div>
                <div>
                  <p className="sophia-scan sophia-terminal-label text-sm">Severity</p>
                  <Badge className={getSeverityStyle(selectedThreat.severity)} style={{ color: getSeverityTextHex(selectedThreat.severity) }}>
                    {selectedThreat.severity}
                  </Badge>
                </div>
                <div>
                  <p className="sophia-scan sophia-terminal-label text-sm">Host</p>
                  <p className="sophia-flicker sophia-terminal-value" style={{ color: '#e6fbff' }}>{selectedThreat.host_id || 'Unknown'}</p>
                </div>
                <div>
                  <p className="sophia-scan sophia-terminal-label text-sm">Timestamp</p>
                  <p className="sophia-flicker sophia-terminal-value" style={{ color: '#e6fbff' }}>{new Date(selectedThreat.timestamp).toLocaleString()}</p>
                </div>
                <div>
                  <p className="sophia-scan sophia-terminal-label text-sm">Full Data</p>
                  <pre className="p-3 rounded-lg text-xs font-mono overflow-auto max-h-64 text-cyan-400" style={{ background: 'rgba(3,9,18,0.76)', border: '1px solid rgba(0,240,255,0.24)' }}>
                    {JSON.stringify(selectedThreat.data, null, 2)}
                  </pre>
                </div>
              </div>
              <Button
                className="w-full mt-4"
                style={{ background: 'linear-gradient(135deg, #00f0ff, #39ff14)', color: '#041018', fontWeight: 700 }}
                onClick={() => setSelectedThreat(null)}
              >
                Close
              </Button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default CommandCenterPage;
