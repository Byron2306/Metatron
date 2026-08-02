import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Workflow, Play, Pause, Plus, Trash2, Edit, Clock, 
  CheckCircle, XCircle, AlertTriangle, Zap, Shield,
  ChevronRight, Settings, RefreshCw, Eye, Activity,
  Brain, Target, Terminal, Cpu, Network, Lock, Key, Tag, Archive
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Switch } from '../components/ui/switch';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../components/ui/tabs';
import { toast } from 'sonner';
import SeraphPageHeader from '../components/SeraphPageHeader';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const SOAR_ACCENTS = {
  cyan: { border: '#87d9df', glow: 'rgba(135,217,223,0.1)', text: '#d9f3f8' },
  green: { border: '#7ce2a3', glow: 'rgba(124,226,163,0.12)', text: '#dcffe8' },
  gold: { border: '#e8c76d', glow: 'rgba(232,199,109,0.12)', text: '#fff1cb' },
  rose: { border: '#f08fb7', glow: 'rgba(240,143,183,0.12)', text: '#ffd9e2' },
  violet: { border: '#c5a2eb', glow: 'rgba(197,162,235,0.12)', text: '#f0ddff' },
};

const soarPanelStyle = (accent) => ({
  background: 'linear-gradient(160deg, rgba(8,18,34,0.92), rgba(3,9,18,0.96))',
  border: `1px solid ${accent.border}`,
  boxShadow: `0 0 12px ${accent.glow}, inset 0 0 8px rgba(0,240,255,0.025)`,
  borderRadius: '14px',
});

const SOARPage = () => {
  const { token } = useAuth();
  const [stats, setStats] = useState(null);
  const [playbooks, setPlaybooks] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [aiPlaybooks, setAiPlaybooks] = useState([]);
  const [executions, setExecutions] = useState([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('all');

  const headers = { Authorization: `Bearer ${token}` };

  // AI-Agentic Defense Playbooks (loaded from YAML config)
  const AI_PLAYBOOK_DEFINITIONS = [
    {
      id: 'AI-RECON-DEGRADE-01',
      name: 'Machine-Paced Recon Loop — Degrade + Observe',
      trigger: 'cli.session_summary',
      description: 'Detect and slow down machine-paced reconnaissance. Applies soft throttle and latency injection.',
      category: 'ai_defense',
      conditions: { machine_likelihood: '≥ 0.80', dominant_intents: ['recon'], burstiness: '≥ 0.75' },
      actions: ['tag_session', 'throttle_cli', 'inject_latency', 'capture_triage_bundle', 'notify'],
      severity: 'medium',
      status: 'active'
    },
    {
      id: 'AI-DECOY-HIT-CONTAIN-01',
      name: 'Decoy/Honey Token Hit — Immediate Containment',
      trigger: 'deception.hit',
      description: 'Immediately isolate host when a honey token is accessed. High confidence intrusion indicator.',
      category: 'ai_defense',
      conditions: { severity: ['high', 'critical'], token_accessed: true },
      actions: ['isolate_host', 'capture_triage_bundle', 'kill_process_tree', 'notify', 'create_ticket'],
      severity: 'critical',
      status: 'active'
    },
    {
      id: 'AI-CRED-ACCESS-RESP-01',
      name: 'Credential Access Pattern — Decoy + Credential Controls',
      trigger: 'cli.session_summary',
      description: 'AI-style credential access detected. Triggers credential rotation and hard throttling.',
      category: 'ai_defense',
      conditions: { machine_likelihood: '≥ 0.80', dominant_intents: ['credential_access'] },
      actions: ['rotate_credentials', 'throttle_cli', 'inject_latency', 'capture_triage_bundle', 'notify'],
      severity: 'high',
      status: 'active'
    },
    {
      id: 'AI-PIVOT-CONTAIN-01',
      name: 'Autonomous Pivot / Toolchain Switching — Contain Fast',
      trigger: 'cli.session_summary',
      description: 'Fast tool switching with lateral movement intent. Immediate host isolation.',
      category: 'ai_defense',
      conditions: { machine_likelihood: '≥ 0.80', tool_switch_latency: '≤ 300ms', dominant_intents: ['lateral_movement', 'privilege_escalation'] },
      actions: ['isolate_host', 'capture_triage_bundle', 'notify', 'create_ticket'],
      severity: 'critical',
      status: 'active'
    },
    {
      id: 'AI-EXFIL-PREP-CUT-01',
      name: 'Exfil Prep — Cut Egress + Snapshot',
      trigger: 'cli.session_summary',
      description: 'Detect data staging and exfiltration preparation. Cut network egress immediately.',
      category: 'ai_defense',
      conditions: { machine_likelihood: '≥ 0.80', dominant_intents: ['exfil_prep', 'data_staging'] },
      actions: ['isolate_host', 'capture_triage_bundle', 'notify', 'create_ticket'],
      severity: 'critical',
      status: 'active'
    },
    {
      id: 'AI-HIGHCONF-ERADICATE-01',
      name: 'High Confidence Agentic Intrusion — Full Containment',
      trigger: 'cli.session_summary',
      description: 'Machine likelihood ≥ 0.92 with decoy touched. Full containment and eradication.',
      category: 'ai_defense',
      conditions: { machine_likelihood: '≥ 0.92', decoy_touched: true },
      actions: ['isolate_host', 'kill_process_tree', 'capture_memory_snapshot', 'capture_triage_bundle', 'notify', 'create_ticket'],
      severity: 'critical',
      status: 'active'
    }
  ];

  const [benchExecutions, setBenchExecutions] = useState([]);
  const [benchLoaded, setBenchLoaded] = useState(false);

  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, 15000);
    return () => clearInterval(id);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  // Load the 285 real SOAR test-bench executions baked into /public.
  useEffect(() => {
    if (benchLoaded) return;
    fetch('/soar_real_executions.json')
      .then((r) => (r.ok ? r.json() : []))
      .then((data) => {
        if (Array.isArray(data)) setBenchExecutions(data);
        setBenchLoaded(true);
      })
      .catch(() => setBenchLoaded(true));
  }, [benchLoaded]);

  const fetchData = async () => {
    try {
      const [statsRes, playbooksRes, templatesRes, executionsRes] = await Promise.all([
        axios.get(`${API}/soar/stats`, { headers }).catch(() => null),
        axios.get(`${API}/soar/playbooks`, { headers }).catch(() => null),
        axios.get(`${API}/soar/templates`, { headers }).catch(() => null),
        axios.get(`${API}/soar/executions?limit=20`, { headers }).catch(() => null),
      ]);
      if (statsRes?.data) setStats(statsRes.data);
      if (playbooksRes?.data) setPlaybooks(playbooksRes.data.playbooks || []);
      if (templatesRes?.data) setTemplates(templatesRes.data.templates || []);
      setAiPlaybooks(AI_PLAYBOOK_DEFINITIONS);
      if (executionsRes?.data) setExecutions(executionsRes.data.executions || []);
    } catch (err) {
      // Soft fail — keep cached data
    } finally {
      setLoading(false);
    }
  };

  const handleTogglePlaybook = async (playbookId) => {
    try {
      await axios.post(`${API}/soar/playbooks/${playbookId}/toggle`, {}, { headers });
      toast.success('Playbook status updated');
      fetchData();
    } catch (err) {
      toast.error('Failed to toggle playbook');
    }
  };

  const handleExecutePlaybook = async (playbookId) => {
    try {
      const res = await axios.post(`${API}/soar/playbooks/${playbookId}/execute`, {
        trigger_type: 'manual',
        severity: 'medium'
      }, { headers });
      toast.success('Playbook executed successfully');
      fetchData();
    } catch (err) {
      toast.error('Failed to execute playbook');
    }
  };

  const getStatusColor = (status) => {
    switch(status) {
      case 'completed': return 'text-green-400 bg-green-500/10 border-green-500/30';
      case 'failed': return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'partial': return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'running': return 'text-fuchsia-300 bg-fuchsia-500/10 border-fuchsia-500/30';
      default: return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    }
  };

  const getTriggerIcon = (trigger) => {
    switch(trigger) {
      case 'malware_found': return <Shield className="w-4 h-4 text-red-400" />;
      case 'ransomware_detected': return <AlertTriangle className="w-4 h-4 text-red-400" />;
      case 'ioc_match': return <Zap className="w-4 h-4 text-amber-400" />;
      case 'suspicious_process': return <Activity className="w-4 h-4 text-purple-400" />;
      case 'honeypot_triggered': return <Eye className="w-4 h-4" style={{ color: '#ff8ad9' }} />;
      case 'cli.session_summary': return <Brain className="w-4 h-4 text-purple-400" />;
      case 'deception.hit': return <Target className="w-4 h-4 text-red-400" />;
      default: return <Workflow className="w-4 h-4 text-slate-400" />;
    }
  };

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low': return 'bg-green-500/20 text-green-400 border-green-500/30';
      default: return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  const getActionIcon = (action) => {
    if (action.includes('isolate') || action.includes('block')) return <Lock className="w-3 h-3" />;
    if (action.includes('kill') || action.includes('terminate')) return <XCircle className="w-3 h-3" />;
    if (action.includes('capture') || action.includes('triage') || action.includes('memory')) return <Terminal className="w-3 h-3" />;
    if (action.includes('notify') || action.includes('alert')) return <Activity className="w-3 h-3" />;
    if (action.includes('throttle') || action.includes('latency') || action.includes('tarpit')) return <Cpu className="w-3 h-3" />;
    if (action.includes('decoy') || action.includes('honeypot') || action.includes('disinfo')) return <Shield className="w-3 h-3" />;
    if (action.includes('rotate') || action.includes('credential')) return <Key className="w-3 h-3" />;
    if (action.includes('tag') || action.includes('session')) return <Tag className="w-3 h-3" />;
    if (action.includes('quarantine') || action.includes('sandbox')) return <Archive className="w-3 h-3" />;
    return <Zap className="w-3 h-3" />;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="w-8 h-8 animate-spin" style={{ color: '#f0ddff' }} />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6" data-testid="soar-page" data-accent="green">
      <SeraphPageHeader
        eyebrow="seraph · response · ai playbooks"
        title="SOAR Playbooks"
        tagline="> security orchestration, automation, response, and machine-paced defense workflows"
        accent="green"
        status={activeTab === 'ai' ? 'AI DEFENSE' : 'AUTOMATION READY'}
        actions={
          <Button onClick={fetchData} variant="outline" style={{ background: 'rgba(240,143,183,0.08)', borderColor: 'rgba(240,143,183,0.38)', color: '#ffd9e2', boxShadow: '0 0 10px rgba(240,143,183,0.12)' }}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        }
      />

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          className="rounded-lg p-4"
          style={soarPanelStyle(SOAR_ACCENTS.cyan)}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center">
              <Workflow className="w-5 h-5" style={{ color: '#ff8ad9' }} />
            </div>
            <div>
              <p className="sophia-terminal-label text-sm">Total Playbooks</p>
              <p className="sophia-flicker sophia-terminal-value text-2xl font-bold" style={{ color: SOAR_ACCENTS.cyan.text }}>{stats?.total_playbooks || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="rounded-lg p-4"
          style={soarPanelStyle(SOAR_ACCENTS.green)}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
              <Play className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="sophia-terminal-label text-sm">Active</p>
              <p className="sophia-flicker sophia-terminal-value text-2xl font-bold" style={{ color: SOAR_ACCENTS.green.text }}>{stats?.active_playbooks || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          className="rounded-lg p-4"
          style={soarPanelStyle(SOAR_ACCENTS.gold)}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ background: 'rgba(255,209,102,0.12)' }}>
              <Activity className="w-5 h-5" style={{ color: '#ffd166' }} />
            </div>
            <div>
              <p className="sophia-terminal-label text-sm">Executions</p>
              <p className="sophia-flicker sophia-terminal-value text-2xl font-bold" style={{ color: SOAR_ACCENTS.gold.text }}>{stats?.total_executions || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
          className="rounded-lg p-4"
          style={soarPanelStyle(SOAR_ACCENTS.green)}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
              <CheckCircle className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="sophia-terminal-label text-sm">Success Rate</p>
              <p className="sophia-flicker sophia-terminal-value text-2xl font-bold" style={{ color: SOAR_ACCENTS.green.text }}>{stats?.success_rate || 0}%</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}
          className="rounded-lg p-4"
          style={soarPanelStyle(SOAR_ACCENTS.rose)}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center">
              <XCircle className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <p className="sophia-terminal-label text-sm">Failed</p>
              <p className="sophia-flicker sophia-terminal-value text-2xl font-bold" style={{ color: SOAR_ACCENTS.rose.text }}>{stats?.executions_failed || 0}</p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Playbooks Section with Tabs */}
      <Card style={soarPanelStyle(SOAR_ACCENTS.cyan)}>
        <CardHeader>
          <CardTitle className="text-white flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Workflow className="w-5 h-5" style={{ color: '#ff8ad9' }} />
              <span className="sophia-terminal-heading">Playbooks</span>
            </div>
            <Tabs value={activeTab} onValueChange={setActiveTab}>
              <TabsList style={{ background: 'linear-gradient(135deg, rgba(8,20,38,0.82), rgba(4,11,22,0.9))', border: '1px solid rgba(197,162,235,0.18)' }}>
                <TabsTrigger value="all" className="data-[state=active]:text-white" style={{ color: '#d7dff1', textTransform: 'uppercase', letterSpacing: '0.12em', fontFamily: "'FfMoon', 'Orbitron', sans-serif" }}>
                  All ({playbooks.length})
                </TabsTrigger>
                <TabsTrigger value="templates" className="data-[state=active]:text-white" style={{ color: '#d7dff1', textTransform: 'uppercase', letterSpacing: '0.12em', fontFamily: "'FfMoon', 'Orbitron', sans-serif" }}>
                  Templates ({templates.length})
                </TabsTrigger>
                <TabsTrigger value="ai" className="data-[state=active]:text-white" style={{ color: '#d7dff1', textTransform: 'uppercase', letterSpacing: '0.12em', fontFamily: "'FfMoon', 'Orbitron', sans-serif" }}>
                  <Brain className="w-4 h-4 mr-1" />
                  AI Defense ({aiPlaybooks.length})
                </TabsTrigger>
              </TabsList>
            </Tabs>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {/* Standard Playbooks */}
          {activeTab === 'all' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {playbooks.map((pb) => (
                <motion.div
                  key={pb.id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="p-4 rounded-lg"
                  style={soarPanelStyle(pb.status === 'active' ? SOAR_ACCENTS.cyan : SOAR_ACCENTS.gold)}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      {getTriggerIcon(pb.trigger)}
                      <div>
                        <h3 className="sophia-flicker sophia-terminal-value text-base" style={{ color: '#f5fbff', fontSize: '1rem' }}>{pb.name}</h3>
                        <p className="sophia-terminal-meta text-xs">{pb.description}</p>
                      </div>
                    </div>
                    <Switch 
                      checked={pb.status === 'active'} 
                      onCheckedChange={() => handleTogglePlaybook(pb.id)}
                    />
                  </div>

                  <div className="flex flex-wrap gap-2 mb-3">
                    <Badge variant="outline" className="text-xs" style={{ color: '#ffd7a1', borderColor: 'rgba(255,209,102,0.3)' }}>
                      {pb.trigger.replace(/_/g, ' ')}
                    </Badge>
                    <Badge variant="outline" className="text-xs text-purple-400 border-purple-500/30">
                      {pb.steps?.length || 0} steps
                    </Badge>
                    {pb.execution_count > 0 && (
                      <Badge variant="outline" className="text-xs text-green-400 border-green-500/30">
                        {pb.execution_count} runs
                      </Badge>
                    )}
                  </div>

                  <div className="flex items-center justify-between text-xs text-slate-500">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {pb.last_executed ? new Date(pb.last_executed).toLocaleString() : 'Never executed'}
                    </span>
                    <div className="flex gap-2">
                      <Button 
                        size="sm" 
                        variant="ghost" 
                        className="h-7 px-2 text-slate-400 hover:text-white"
                        onClick={() => setSelectedPlaybook(pb)}
                      >
                        <Eye className="w-4 h-4" />
                      </Button>
                      <Button 
                        size="sm" 
                        variant="ghost" 
                        className="h-7 px-2 text-green-400 hover:text-green-300"
                        onClick={() => handleExecutePlaybook(pb.id)}
                        disabled={pb.status !== 'active'}
                      >
                        <Play className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          )}

          {/* Templates Library */}
          {activeTab === 'templates' && (
            <div className="space-y-4">
              <div className="p-4 bg-green-500/10 border border-green-500/30 rounded-lg mb-4">
                <div className="flex items-center gap-3 mb-2">
                  <Shield className="w-6 h-6 text-green-400" />
                  <div>
                    <h3 className="text-white font-semibold">Playbook Templates Library</h3>
                    <p className="text-slate-400 text-sm">Pre-built response templates for common security scenarios</p>
                  </div>
                </div>
                <p className="text-green-300 text-xs">
                  Click "Deploy" to create a new playbook from any template. Templates include data breach, credential theft, APT detection, and more.
                </p>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {templates.map((tpl, idx) => (
                  <motion.div
                    key={tpl.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.05 }}
                    className="p-4 rounded-lg transition-all"
                    style={soarPanelStyle(SOAR_ACCENTS.green)}
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-start gap-3">
                        <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
                          <Shield className="w-5 h-5 text-green-400" />
                        </div>
                        <div>
                          <h3 className="sophia-flicker sophia-terminal-value text-base" style={{ color: '#f5fbff', fontSize: '1rem' }}>{tpl.name}</h3>
                          <p className="sophia-terminal-meta text-xs mt-1 line-clamp-2">{tpl.description}</p>
                        </div>
                      </div>
                    </div>
                    
                    <div className="flex flex-wrap gap-2 mb-3">
                      <Badge variant="outline" className="text-xs text-cyan-400 border-cyan-500/30">
                        {tpl.category?.replace(/_/g, ' ')}
                      </Badge>
                      <Badge variant="outline" className="text-xs text-purple-400 border-purple-500/30">
                        {tpl.steps?.length || 0} steps
                      </Badge>
                      {tpl.is_official && (
                        <Badge variant="outline" className="text-xs text-green-400 border-green-500/30">
                          Official
                        </Badge>
                      )}
                    </div>

                    {tpl.tags && tpl.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mb-3">
                        {tpl.tags.slice(0, 4).map((tag, i) => (
                            <span key={i} className="px-2 py-0.5 rounded text-xs" style={{ background: 'rgba(3,9,18,0.72)', border: '1px solid rgba(102,230,255,0.22)', color: '#cbefff' }}>
                            {tag}
                          </span>
                        ))}
                        {tpl.tags.length > 4 && (
                          <span className="px-2 py-0.5 rounded text-xs" style={{ background: 'rgba(3,9,18,0.72)', border: '1px solid rgba(102,230,255,0.18)', color: '#95c9d8' }}>
                            +{tpl.tags.length - 4}
                          </span>
                        )}
                      </div>
                    )}
                    
                    <div className="flex items-center justify-between pt-2 border-t border-slate-700">
                      <span className="text-xs text-slate-500">{tpl.id}</span>
                      <Button 
                        size="sm" 
                        className="h-7 bg-green-500/20 hover:bg-green-500/30 text-green-400"
                        onClick={() => {
                          toast.success(`Template "${tpl.name}" ready to deploy`);
                        }}
                      >
                        <Plus className="w-3 h-3 mr-1" />
                        Deploy
                      </Button>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
          )}

          {/* AI-Agentic Defense Playbooks */}
          {activeTab === 'ai' && (
            <div className="space-y-4">
              <div className="p-4 bg-purple-500/10 border border-purple-500/30 rounded-lg mb-4">
                <div className="flex items-center gap-3 mb-2">
                  <Brain className="w-6 h-6 text-purple-400" />
                  <div>
                    <h3 className="text-white font-semibold">AI-Agentic Defense Playbook Pack</h3>
                    <p className="text-slate-400 text-sm">Machine-paced intrusion detection and autonomous response</p>
                  </div>
                </div>
                <p className="text-purple-300 text-xs">
                  These playbooks analyze CLI session patterns via the Cognition Engine to detect and disrupt AI-driven attacks.
                  Responses follow the "Slow & Poison" philosophy: degrade operations before full containment.
                </p>
              </div>
              
              <div className="grid grid-cols-1 gap-4">
                {aiPlaybooks.map((pb, idx) => (
                  <motion.div
                    key={pb.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.1 }}
                    className="p-4 rounded-lg transition-all"
                    style={soarPanelStyle(SOAR_ACCENTS.violet)}
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-start gap-3">
                        <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center">
                          {getTriggerIcon(pb.trigger)}
                        </div>
                        <div>
                          <h3 className="sophia-flicker sophia-terminal-value text-base" style={{ color: '#f5fbff', fontSize: '1rem' }}>{pb.name}</h3>
                          <p className="sophia-terminal-meta text-sm mt-1">{pb.description}</p>
                        </div>
                      </div>
                      <Badge className={getSeverityColor(pb.severity)}>
                        {pb.severity.toUpperCase()}
                      </Badge>
                    </div>
                    
                    {/* Trigger Conditions */}
                    <div className="mb-3 p-3 bg-slate-900/50 rounded-lg">
                      <p className="sophia-scan sophia-terminal-label text-xs mb-2 font-semibold">Trigger Conditions</p>
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(pb.conditions).map(([key, value]) => (
                          <span key={key} className="px-2 py-1 rounded text-xs" style={{ background: 'rgba(3,9,18,0.82)', border: '1px solid rgba(198,146,255,0.24)', color: '#efdfff' }}>
                            <span className="text-cyan-400">{key.replace(/_/g, ' ')}</span>: {Array.isArray(value) ? value.join(', ') : String(value)}
                          </span>
                        ))}
                      </div>
                    </div>
                    
                    {/* Actions */}
                    <div className="mb-3">
                      <p className="sophia-scan sophia-terminal-label text-xs mb-2 font-semibold">Response Actions</p>
                      <div className="flex flex-wrap gap-2">
                        {pb.actions.map((action, i) => (
                          <span key={i} className="px-2 py-1 rounded text-xs flex items-center gap-1" style={{ background: 'rgba(198,146,255,0.18)', border: '1px solid rgba(198,146,255,0.26)', color: '#efdfff' }}>
                            {getActionIcon(action)}
                            {action.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    </div>
                    
                    <div className="flex items-center justify-between text-xs text-slate-500">
                      <span className="flex items-center gap-1 text-purple-400">
                        <Cpu className="w-3 h-3" />
                        ID: {pb.id}
                      </span>
                      <Badge variant="outline" className="text-green-400 border-green-500/30">
                        <CheckCircle className="w-3 h-3 mr-1" />
                        {pb.status}
                      </Badge>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* === REAL TEST-BENCH EXECUTIONS (compiled_evidence_s5_real_executions_285.json) === */}
      <Card style={soarPanelStyle(SOAR_ACCENTS.rose)}>
        <CardHeader>
          <div className="flex items-center justify-between flex-wrap gap-2">
            <CardTitle className="text-white flex items-center gap-3">
              <Archive className="w-5 h-5" style={{ color: '#ff2bd6', filter: 'drop-shadow(0 0 6px rgba(255,43,214,0.6))' }} />
              <span style={{
                fontFamily: "'Orbitron', monospace",
                fontWeight: 800,
                letterSpacing: '0.06em',
                textTransform: 'uppercase',
              }}>Real Test-Bench Executions</span>
              <Badge style={{
                background: 'linear-gradient(135deg, rgba(255,43,214,0.2), rgba(0,240,255,0.15))',
                border: '1px solid rgba(255,43,214,0.5)',
                color: '#ff8ad9',
                fontFamily: "'JetBrains Mono', monospace",
                letterSpacing: '0.18em',
                textShadow: '0 0 8px rgba(255,43,214,0.6)',
              }}>{benchExecutions.length} runs</Badge>
            </CardTitle>
            <span style={{ fontSize: 11, color: '#9ed3e6', fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.18em' }}>
              GHA · DOCKER · ATOMIC-RED-TEAM
            </span>
          </div>
        </CardHeader>
        <CardContent>
          {/* Bench summary tiles */}
          {benchExecutions.length > 0 && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
              {(() => {
                const success = benchExecutions.filter((e) => e.status === 'success').length;
                const real = benchExecutions.filter((e) => e.outcome === 'real_execution').length;
                const techSet = new Set();
                benchExecutions.forEach((e) => (e.techniques_executed || e.techniques || []).forEach((t) => techSet.add(t)));
                const runners = new Set(benchExecutions.map((e) => e.runner).filter(Boolean));
                return [
                  { label: 'TOTAL RUNS', val: benchExecutions.length, c: '#00f0ff' },
                  { label: 'SUCCESS', val: success, c: '#39ff14' },
                  { label: 'REAL EXEC', val: real, c: '#ff2bd6' },
                  { label: 'UNIQUE TECHNIQUES', val: techSet.size, c: '#bc13fe' },
                ].map((m) => (
                  <div key={m.label}
                    className="p-3 text-center"
                    style={{
                      background: `linear-gradient(160deg, ${m.c}10, rgba(2,8,19,0.86))`,
                      border: `1px solid ${m.c}55`,
                      boxShadow: `inset 0 0 8px ${m.c}10`,
                      borderRadius: '10px',
                    }}>
                    <p style={{
                      fontFamily: "'Orbitron', monospace",
                      fontSize: '1.7rem',
                      fontWeight: 900,
                      color: m.c,
                      textShadow: `0 0 10px ${m.c}99`,
                      lineHeight: 1,
                    }}>{m.val}</p>
                    <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: '#9ed3e6', letterSpacing: '0.32em', marginTop: 6 }}>
                      {m.label}
                    </p>
                  </div>
                ));
              })()}
            </div>
          )}

          {benchExecutions.length > 0 && (
            <div className="space-y-1.5 max-h-[420px] overflow-y-auto pr-2">
              {benchExecutions.slice(0, 60).map((exec, idx) => {
                const ok = exec.status === 'success';
                const accent = ok ? '#39ff14' : '#ff3838';
                const techs = exec.techniques_executed || exec.techniques || [];
                return (
                  <div key={exec.run_id || idx}
                    className="p-2.5 flex items-center justify-between gap-3"
                    style={{
                      background: 'linear-gradient(160deg, rgba(9,18,38,0.86), rgba(2,8,19,0.92))',
                      border: `1px solid ${accent}33`,
                      borderLeft: `2px solid ${accent}`,
                    }}>
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <span style={{
                        width: 8, height: 8, borderRadius: '50%',
                        background: accent,
                        boxShadow: `0 0 6px ${accent}, 0 0 14px ${accent}aa`,
                        flexShrink: 0,
                      }}/>
                      <div className="min-w-0 flex-1">
                        <p style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: 11,
                          color: '#e6fbff',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}>{exec.job_name || exec.message || exec.runner}</p>
                        <p style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: 9,
                          color: '#9ed3e6',
                          letterSpacing: '0.06em',
                        }}>
                          {techs.slice(0, 4).join(' · ') || '—'}{techs.length > 4 ? ` +${techs.length - 4}` : ''}
                        </p>
                      </div>
                    </div>
                    <span style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 9,
                      letterSpacing: '0.18em',
                      color: accent,
                      textShadow: `0 0 6px ${accent}99`,
                      flexShrink: 0,
                    }}>
                      {exec.runner?.toUpperCase() || 'BENCH'}
                    </span>
                  </div>
                );
              })}
              {benchExecutions.length > 60 && (
                <p className="text-center pt-2" style={{ color: '#9ed3e6', fontFamily: "'JetBrains Mono', monospace", fontSize: 10, letterSpacing: '0.18em' }}>
                  ▾ {benchExecutions.length - 60} more runs in archive ▾
                </p>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Recent Executions (live API) */}
      <Card style={soarPanelStyle(SOAR_ACCENTS.gold)}>
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-blue-400" />
            <span className="sophia-terminal-heading">Recent Executions (live)</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {executions.length > 0 ? (
            <div className="space-y-2">
              {executions.map((exec) => (
                <div key={exec.id}
                  className="flex items-center justify-between p-3 rounded-lg"
                  style={{ background: 'linear-gradient(140deg, rgba(8,20,38,0.9), rgba(3,9,18,0.96))', border: '1px solid rgba(255,209,102,0.22)' }}>
                  <div className="flex items-center gap-4">
                    <div className={`w-8 h-8 rounded flex items-center justify-center ${getStatusColor(exec.status)}`}>
                      {exec.status === 'completed' ? <CheckCircle className="w-4 h-4" /> :
                       exec.status === 'failed' ? <XCircle className="w-4 h-4" /> :
                       exec.status === 'partial' ? <AlertTriangle className="w-4 h-4" /> :
                       <RefreshCw className="w-4 h-4 animate-spin" />}
                    </div>
                    <div>
                      <p className="sophia-flicker sophia-terminal-value text-sm font-medium" style={{ color: '#ffffff', fontSize: '0.92rem' }}>{exec.playbook_name}</p>
                      <p className="sophia-terminal-meta text-xs">
                        {exec.step_results?.length || 0} steps executed
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <Badge variant="outline" className={getStatusColor(exec.status)}>
                      {exec.status}
                    </Badge>
                    <span className="sophia-terminal-meta text-xs">
                      {new Date(exec.started_at).toLocaleString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-slate-400">
              <Activity className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No live executions in the current window</p>
              <p className="text-sm">See the bench archive above for the 285 historic real runs.</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Playbook Detail Modal */}
      {selectedPlaybook && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4"
          onClick={() => setSelectedPlaybook(null)}>
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="bg-slate-800 border border-slate-700 rounded-lg w-full max-w-2xl max-h-[80vh] overflow-y-auto"
            onClick={e => e.stopPropagation()}
          >
            <div className="p-6 border-b border-slate-700">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {getTriggerIcon(selectedPlaybook.trigger)}
                  <div>
                    <h2 className="text-lg font-semibold text-white">{selectedPlaybook.name}</h2>
                    <p className="text-sm text-slate-400">{selectedPlaybook.description}</p>
                  </div>
                </div>
                <button onClick={() => setSelectedPlaybook(null)} className="text-slate-400 hover:text-white">
                  ×
                </button>
              </div>
            </div>
            
            <div className="p-6 space-y-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-400 mb-2">Trigger</h3>
                <Badge className="bg-cyan-500/20 text-cyan-400 border-cyan-500/30">
                  {selectedPlaybook.trigger.replace(/_/g, ' ').toUpperCase()}
                </Badge>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-slate-400 mb-2">Conditions</h3>
                <pre className="text-xs bg-slate-900 p-3 rounded overflow-auto text-slate-300">
                  {JSON.stringify(selectedPlaybook.trigger_conditions, null, 2)}
                </pre>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-slate-400 mb-2">Steps ({selectedPlaybook.steps?.length || 0})</h3>
                <div className="space-y-2">
                  {selectedPlaybook.steps?.map((step, idx) => (
                    <div key={idx} className="flex items-center gap-3 p-3 bg-slate-900/50 rounded-lg">
                      <div className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-xs font-bold">
                        {idx + 1}
                      </div>
                      <div className="flex-1">
                        <p className="text-white text-sm font-medium">
                          {step.action.replace(/_/g, ' ').toUpperCase()}
                        </p>
                        <p className="text-slate-400 text-xs">
                          Timeout: {step.timeout}s | Continue on failure: {step.continue_on_failure ? 'Yes' : 'No'}
                        </p>
                      </div>
                      <ChevronRight className="w-4 h-4 text-slate-500" />
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex gap-3 pt-4 border-t border-slate-700">
                <Button
                  className="flex-1 seraph-btn-primary"
                  onClick={() => {
                    handleExecutePlaybook(selectedPlaybook.id);
                    setSelectedPlaybook(null);
                  }}
                  disabled={selectedPlaybook.status !== 'active'}
                >
                  <Play className="w-4 h-4 mr-2" />
                  Execute Now
                </Button>
              </div>
            </div>
          </motion.div>
        </div>
      )}
    </div>
  );
};

export default SOARPage;
