import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Brain, Shield, AlertTriangle, Activity, Eye, Target,
  Zap, Lock, Unlock, RefreshCw, ChevronRight, Search,
  Database, Clock, Users, Cpu, Network, Terminal,
  TrendingUp, BarChart3, PieChart, FileText, BookOpen,
  Crosshair, Radio, Bot, AlertOctagon, ShieldAlert,
  Gauge, Timer, GitBranch
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '../components/ui/card';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../components/ui/tabs';
import { Progress } from '../components/ui/progress';
import { toast } from 'sonner';
import { API_ROOT as API } from '../lib/api';
import SeraphPageHeader from '../components/SeraphPageHeader';

const AI_INTEL_ACCENTS = {
  magenta: { border: 'rgba(255,138,217,0.34)', glow: 'rgba(255,138,217,0.12)' },
  violet: { border: 'rgba(197,162,235,0.32)', glow: 'rgba(197,162,235,0.12)' },
  gold: { border: 'rgba(255,209,102,0.3)', glow: 'rgba(255,209,102,0.1)' },
  green: { border: 'rgba(124,226,163,0.28)', glow: 'rgba(124,226,163,0.1)' },
};

const aiIntelPanelStyle = (accent) => ({
  background: 'linear-gradient(160deg, rgba(8,18,34,0.92), rgba(3,9,18,0.96))',
  border: `1px solid ${accent.border}`,
  boxShadow: `0 0 14px ${accent.glow}, inset 0 0 8px rgba(255,255,255,0.02)`,
  clipPath: 'polygon(10px 0, 100% 0, 100% calc(100% - 10px), calc(100% - 10px) 100%, 0 100%, 0 10px)',
});

const formatPercent = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return '0%';
  return `${(numeric * 100).toFixed(0)}%`;
};

const formatCount = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return '0';
  return numeric.toLocaleString();
};

const formatAabTimestamp = (value) => {
  if (!value || value.length < 15) return value || 'unknown';
  return `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6, 8)} ${value.slice(9, 11)}:${value.slice(11, 13)}Z`;
};

const getAgenticityColor = (classification) => {
  switch (classification) {
    case 'autonomous_agent_high': return 'text-red-400 border-red-500/30 bg-red-500/10';
    case 'autonomous_agent_medium': return 'text-orange-400 border-orange-500/30 bg-orange-500/10';
    case 'automation_suspected': return 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10';
    case 'human_or_script_low': return 'text-green-400 border-green-500/30 bg-green-500/10';
    default: return 'text-slate-400 border-slate-500/30 bg-slate-500/10';
  }
};

const fetchAabEvidenceSnapshot = async () => {
  try {
    const response = await fetch('/aab-live-latest.json', { cache: 'no-store' });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  }
};


const AIThreatIntelligence = () => {
  const { token } = useAuth();
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  
  // AATL State
  const [aatlSummary, setAatlSummary] = useState(null);
  const [assessments, setAssessments] = useState([]);
  const [strategies, setStrategies] = useState({});
  const [lifecycleStages, setLifecycleStages] = useState({});
  
  // AATR State
  const [aatrSummary, setAatrSummary] = useState(null);
  const [registryEntries, setRegistryEntries] = useState([]);
  const [indicators, setIndicators] = useState([]);
  const [selectedEntry, setSelectedEntry] = useState(null);
  
  // Combined Intelligence
  const [dashboard, setDashboard] = useState(null);
  const [aabEvidence, setAabEvidence] = useState(null);

  const headers = { Authorization: `Bearer ${token}` };

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [
        dashboardRes,
        aatlSummaryRes,
        assessmentsRes,
        strategiesRes,
        stagesRes,
        aatrSummaryRes,
        entriesRes,
        indicatorsRes,
        aabEvidenceRes
      ] = await Promise.all([
        axios.get(`${API}/ai-threats/intelligence/dashboard`, { headers }),
        axios.get(`${API}/ai-threats/aatl/summary`, { headers }),
        axios.get(`${API}/ai-threats/aatl/assessments?min_threat=0&limit=50`, { headers }),
        axios.get(`${API}/ai-threats/aatl/response-strategies`, { headers }),
        axios.get(`${API}/ai-threats/aatl/lifecycle-stages`, { headers }),
        axios.get(`${API}/ai-threats/aatr/summary`, { headers }),
        axios.get(`${API}/ai-threats/aatr/entries?active_only=true`, { headers }),
        axios.get(`${API}/ai-threats/aatr/indicators`, { headers }),
        fetchAabEvidenceSnapshot()
      ]);
      
      setDashboard(dashboardRes.data);
      setAatlSummary(aatlSummaryRes.data);
      setAssessments(assessmentsRes.data.assessments || []);
      setStrategies(strategiesRes.data.strategies || {});
      setLifecycleStages(stagesRes.data.stages || {});
      setAatrSummary(aatrSummaryRes.data);
      setRegistryEntries(entriesRes.data.entries || []);
      setIndicators(indicatorsRes.data.indicators || []);
      setAabEvidence(aabEvidenceRes);
    } catch (err) {
      console.error('Failed to fetch AI threat intelligence:', err);
      toast.error('Failed to load AI threat intelligence');
    } finally {
      setLoading(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  const liveAabClasses = aabEvidence?.classes || [];
  const liveAabSessions = aabEvidence?.sessions || [];
  const agenticityCounts = aabEvidence?.agenticity?.classification_counts || {};

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const getActorTypeIcon = (type) => {
    switch (type) {
      case 'autonomous_agent': return <Bot className="w-5 h-5 text-red-400" />;
      case 'ai_assisted': return <Brain className="w-5 h-5 text-orange-400" />;
      case 'automated_script': return <Terminal className="w-5 h-5 text-yellow-400" />;
      case 'human': return <Users className="w-5 h-5 text-green-400" />;
      default: return <Eye className="w-5 h-5 text-slate-400" />;
    }
  };

  const getThreatColor = (level) => {
    switch (level) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low': return 'bg-green-500/20 text-green-400 border-green-500/30';
      default: return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  const STRATEGY_NEON = {
    observe:   { bg: 'rgba(76,196,255,0.08)',   border: '#4cc4ff', color: '#76e3ff', glow: 'rgba(76,196,255,0.4)'   },
    slow:      { bg: 'rgba(0,240,255,0.08)',    border: '#00f0ff', color: '#aef0ff', glow: 'rgba(0,240,255,0.4)'    },
    poison:    { bg: 'rgba(188,19,254,0.08)',   border: '#bc13fe', color: '#f3beff', glow: 'rgba(188,19,254,0.4)'   },
    deceive:   { bg: 'rgba(255,43,214,0.08)',   border: '#ff2bd6', color: '#ff8ad9', glow: 'rgba(255,43,214,0.4)'   },
    contain:   { bg: 'rgba(255,138,60,0.08)',   border: '#ff8a3c', color: '#ffd47a', glow: 'rgba(255,138,60,0.4)'   },
    eradicate: { bg: 'rgba(255,56,56,0.08)',    border: '#ff3838', color: '#ff8a96', glow: 'rgba(255,56,56,0.4)'    },
  };

  const getStrategyColor = (strategy) => {
    const m = STRATEGY_NEON[strategy];
    return m ? `border` : 'bg-slate-500/20 text-slate-400';
  };

  const getStrategyStyle = (strategy) => {
    const m = STRATEGY_NEON[strategy] || { bg: 'rgba(0,240,255,0.08)', border: '#00f0ff', color: '#aef0ff', glow: 'rgba(0,240,255,0.4)' };
    return {
      background: m.bg,
      borderColor: m.border,
      borderWidth: '1px',
      borderStyle: 'solid',
      boxShadow: `0 0 16px ${m.glow}, -3px 0 10px ${m.glow}, inset 0 0 12px rgba(0,0,0,0.3)`,
      color: m.color,
      clipPath: 'polygon(8px 0,100% 0,100% calc(100% - 8px),calc(100% - 8px) 100%,0 100%,0 8px)',
    };
  };

  const getRiskColor = (risk) => {
    switch (risk) {
      case 'critical': return 'text-red-400';
      case 'high': return 'text-orange-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-green-400';
      default: return 'text-slate-400';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-purple-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="ai-threat-intelligence" data-accent="gold">
      <SeraphPageHeader
        eyebrow="seraph · ai-threat-intel · aatl · aatr"
        title="AI Threat Intelligence"
        tagline="> autonomous agent threat layer · ai threat registry · behavioral detection"
        accent="gold"
        status="MONITORING"
        actions={
          <Button onClick={fetchData} variant="outline" style={{ borderColor: 'rgba(255,138,217,0.34)', color: '#ffd8f4' }}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        }
      />

      {/* Overview Stats */}
      {dashboard && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="p-4" style={aiIntelPanelStyle(AI_INTEL_ACCENTS.magenta)}
          >
            <div className="flex items-center justify-between mb-2">
              <Brain className="w-8 h-8 text-purple-400" />
              <Badge className={getThreatColor(dashboard.combined_threat_score >= 50 ? 'high' : 'medium')}>
                {dashboard.combined_threat_score?.toFixed(0)}% AI Activity
              </Badge>
            </div>
            <div className="text-3xl font-bold text-white">
              {dashboard.aatl?.total_sessions || 0}
            </div>
            <div className="text-slate-400 text-sm">Monitored Sessions</div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="p-4" style={aiIntelPanelStyle(AI_INTEL_ACCENTS.magenta)}
          >
            <div className="flex items-center justify-between mb-2">
              <Bot className="w-8 h-8 text-red-400" />
              <Badge className="bg-red-500/20 text-red-400">Autonomous</Badge>
            </div>
            <div className="text-3xl font-bold text-white">
              {dashboard.aatl?.autonomous_agent_sessions || 0}
            </div>
            <div className="text-slate-400 text-sm">AI Agent Detections</div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="p-4" style={aiIntelPanelStyle(AI_INTEL_ACCENTS.gold)}
          >
            <div className="flex items-center justify-between mb-2">
              <Database className="w-8 h-8 text-cyan-400" />
              <Badge className="bg-cyan-500/20 text-cyan-400">Registry</Badge>
            </div>
            <div className="text-3xl font-bold text-white">
              {dashboard.aatr?.total_entries || 0}
            </div>
            <div className="text-slate-400 text-sm">Known Threat Types</div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="p-4" style={aiIntelPanelStyle(AI_INTEL_ACCENTS.green)}
          >
            <div className="flex items-center justify-between mb-2">
              <AlertTriangle className="w-8 h-8 text-yellow-400" />
              <Badge className="bg-yellow-500/20 text-yellow-400">Active</Badge>
            </div>
            <div className="text-3xl font-bold text-white">
              {dashboard.active_threat_types || 0}
            </div>
            <div className="text-slate-400 text-sm">Active Threat Types</div>
          </motion.div>
        </div>
      )}

      {/* Main Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList style={aiIntelPanelStyle(AI_INTEL_ACCENTS.violet)}>
          <TabsTrigger value="overview" className="data-[state=active]:text-white" style={{ color: '#d7dff1' }}>
            <Eye className="w-4 h-4 mr-2" /> AATL Overview
          </TabsTrigger>
          <TabsTrigger value="assessments" className="data-[state=active]:text-white" style={{ color: '#d7dff1' }}>
            <Target className="w-4 h-4 mr-2" /> Threat Assessments
          </TabsTrigger>
          <TabsTrigger value="registry" className="data-[state=active]:text-white" style={{ color: '#d7dff1' }}>
            <Database className="w-4 h-4 mr-2" /> AATR Registry
          </TabsTrigger>
          <TabsTrigger value="aab-live" className="data-[state=active]:text-white" style={{ color: '#d7dff1' }}>
            <Gauge className="w-4 h-4 mr-2" /> Live AAB
          </TabsTrigger>
          <TabsTrigger value="indicators" className="data-[state=active]:text-white" style={{ color: '#d7dff1' }}>
            <Crosshair className="w-4 h-4 mr-2" /> Detection Indicators
          </TabsTrigger>
        </TabsList>

        {/* AATL Overview Tab */}
        <TabsContent value="overview" className="mt-4 space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Actor Type Distribution */}
            <Card style={aiIntelPanelStyle(AI_INTEL_ACCENTS.violet)}>
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Users className="w-5 h-5 text-purple-400" />
                  Actor Type Distribution
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {Object.entries(aatlSummary?.by_actor_type || {}).map(([type, data]) => (
                    <div key={type} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
                      <div className="flex items-center gap-3">
                        {getActorTypeIcon(type)}
                        <div>
                          <span className="text-white capitalize">{type.replace('_', ' ')}</span>
                          <div className="text-xs text-slate-400">
                            Avg Threat: {data.avg_threat?.toFixed(0) || 0}%
                          </div>
                        </div>
                      </div>
                      <div className="text-right">
                        <Badge variant="outline">{data.count || 0}</Badge>
                        <div className="text-xs text-slate-500 mt-1">
                          Max: {data.max_threat?.toFixed(0) || 0}%
                        </div>
                      </div>
                    </div>
                  ))}
                  {Object.keys(aatlSummary?.by_actor_type || {}).length === 0 && (
                    <div className="text-center py-8 text-slate-400">
                      <Bot className="w-12 h-12 mx-auto mb-2 opacity-50" />
                      <p>No AATL assessments yet</p>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Lifecycle Stage Distribution */}
            <Card style={aiIntelPanelStyle(AI_INTEL_ACCENTS.gold)}>
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <GitBranch className="w-5 h-5 text-cyan-400" />
                  Attack Lifecycle Stages
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {Object.entries(aatlSummary?.by_lifecycle_stage || {}).map(([stage, count]) => (
                    <div key={stage} className="flex items-center gap-3">
                      <div className="w-32 text-sm text-slate-400 capitalize">
                        {stage.replace('_', ' ')}
                      </div>
                      <div className="flex-1">
                        <Progress 
                          value={(count / (aatlSummary?.total_sessions || 1)) * 100} 
                          className="h-2"
                        />
                      </div>
                      <Badge variant="outline" className="w-12 justify-center">{count}</Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Response Strategies */}
            <Card style={aiIntelPanelStyle(AI_INTEL_ACCENTS.green)} className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Shield className="w-5 h-5 text-green-400" />
                  AI-Specific Response Strategies
                </CardTitle>
                <CardDescription>
                  Strategies designed for countering autonomous AI agents
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                  {Object.entries(strategies).map(([key, strategy]) => (
                    <div
                      key={key}
                      className="p-4 transition-all seraph-fx-hover-lift"
                      style={getStrategyStyle(key)}
                    >
                      <div className="text-sm font-bold mb-1" style={{ fontFamily: "'Orbitron', monospace", letterSpacing: '0.1em', color: STRATEGY_NEON[key]?.color || '#aef0ff', textShadow: `0 0 10px ${STRATEGY_NEON[key]?.border || '#00f0ff'}` }}>{(strategy.name || key).toUpperCase()}</div>
                      <div className="text-xs opacity-80 mb-2" style={{ color: STRATEGY_NEON[key]?.color || '#aef0ff', opacity: 0.7 }}>{strategy.description}</div>
                      <div className="text-xs space-y-1">
                        {strategy.actions?.slice(0, 2).map((action, i) => (
                          <div key={i} className="flex items-center gap-1">
                            <ChevronRight className="w-3 h-3" />
                            {action}
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Threat Assessments Tab */}
        <TabsContent value="assessments" className="mt-4">
          <Card style={aiIntelPanelStyle(AI_INTEL_ACCENTS.magenta)}>
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Target className="w-5 h-5 text-red-400" />
                Active AATL Assessments ({assessments.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <AnimatePresence>
                  {assessments.map((assessment, idx) => (
                    <motion.div
                      key={`${assessment.host_id}-${assessment.session_id}`}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: idx * 0.05 }}
                      className="p-4 bg-slate-800/50 rounded-lg border border-slate-700 hover:border-purple-500/50 transition-all"
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center gap-3">
                          {getActorTypeIcon(assessment.actor_type)}
                          <div>
                            <div className="text-white font-medium">
                              {assessment.host_id} / {assessment.session_id}
                            </div>
                            <div className="text-sm text-slate-400">
                              {assessment.actor_type?.replace('_', ' ')} • 
                              Confidence: {(assessment.actor_confidence * 100)?.toFixed(0)}%
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge className={getThreatColor(assessment.threat_level)}>
                            {assessment.threat_level} ({assessment.threat_score?.toFixed(0)}%)
                          </Badge>
                          <Badge className={getStrategyColor(assessment.recommended_strategy)}>
                            {assessment.recommended_strategy}
                          </Badge>
                        </div>
                      </div>

                      {/* Machine vs Human Score */}
                      <div className="grid grid-cols-2 gap-4 mb-3">
                        <div>
                          <div className="flex items-center justify-between text-sm mb-1">
                            <span className="text-slate-400">Machine Plausibility</span>
                            <span className="text-red-400">{(assessment.machine_plausibility * 100)?.toFixed(0)}%</span>
                          </div>
                          <Progress 
                            value={assessment.machine_plausibility * 100} 
                            className="h-2 bg-slate-700"
                          />
                        </div>
                        <div>
                          <div className="flex items-center justify-between text-sm mb-1">
                            <span className="text-slate-400">Human Plausibility</span>
                            <span className="text-green-400">{(assessment.human_plausibility * 100)?.toFixed(0)}%</span>
                          </div>
                          <Progress 
                            value={assessment.human_plausibility * 100} 
                            className="h-2 bg-slate-700"
                          />
                        </div>
                      </div>

                      {/* Intent & Stage */}
                      <div className="flex flex-wrap gap-2 mb-3">
                        <Badge variant="outline" className="text-purple-400 border-purple-500/30">
                          <Brain className="w-3 h-3 mr-1" />
                          Intent: {assessment.intent_accumulation?.primary_intent || 'unknown'}
                        </Badge>
                        <Badge variant="outline" className="text-cyan-400 border-cyan-500/30">
                          <GitBranch className="w-3 h-3 mr-1" />
                          Stage: {assessment.lifecycle_stage?.replace('_', ' ')}
                        </Badge>
                        <Badge variant="outline" className="text-yellow-400 border-yellow-500/30">
                          <Target className="w-3 h-3 mr-1" />
                          Goal Convergence: {(assessment.intent_accumulation?.goal_convergence_score * 100)?.toFixed(0)}%
                        </Badge>
                      </div>

                      {/* Indicators */}
                      {assessment.indicators?.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {assessment.indicators.map((indicator, i) => (
                            <span key={i} className="px-2 py-1 rounded text-xs bg-slate-700 text-slate-300">
                              {indicator}
                            </span>
                          ))}
                        </div>
                      )}

                      {/* Recommended Actions */}
                      {assessment.recommended_actions?.length > 0 && (
                        <div className="mt-3 pt-3 border-t border-slate-700">
                          <div className="text-xs text-slate-400 mb-2">Recommended Actions:</div>
                          <div className="flex flex-wrap gap-2">
                            {assessment.recommended_actions.map((action, i) => (
                              <Badge key={i} variant="outline" className="text-xs">
                                {action.replace('_', ' ')}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </motion.div>
                  ))}
                </AnimatePresence>

                {assessments.length === 0 && (
                  <div className="text-center py-12 text-slate-400">
                    <Target className="w-12 h-12 mx-auto mb-4 opacity-50" />
                    <p>No threat assessments yet. CLI events will generate AATL assessments.</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* AATR Registry Tab */}
        <TabsContent value="registry" className="mt-4">
          <Card style={aiIntelPanelStyle(AI_INTEL_ACCENTS.gold)}>
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Database className="w-5 h-5 text-cyan-400" />
                Autonomous AI Threat Registry ({registryEntries.length} Core / {liveAabClasses.length} Live AAB Classes)
              </CardTitle>
              <CardDescription>
                Defensive intelligence catalog plus the latest 38-class AAB live evidence matrix
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {registryEntries.map((entry, idx) => (
                  <motion.div
                    key={entry.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.1 }}
                    className={`p-4 rounded-lg border transition-all cursor-pointer ${
                      selectedEntry?.id === entry.id 
                        ? 'bg-purple-500/10 border-purple-500/50' 
                        : 'bg-slate-800/50 border-slate-700 hover:border-slate-600'
                    }`}
                    onClick={() => setSelectedEntry(selectedEntry?.id === entry.id ? null : entry)}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-3">
                        <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${
                          entry.risk_profile === 'critical' ? 'bg-red-500/20' :
                          entry.risk_profile === 'high' ? 'bg-orange-500/20' :
                          'bg-yellow-500/20'
                        }`}>
                          <Bot className={`w-6 h-6 ${getRiskColor(entry.risk_profile)}`} />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-white font-semibold">{entry.name}</span>
                            <Badge variant="outline" className="text-xs">{entry.id}</Badge>
                          </div>
                          <div className="text-sm text-slate-400">
                            {entry.classification?.replace('_', ' ')}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge className={getThreatColor(entry.risk_profile)}>
                          {entry.risk_profile}
                        </Badge>
                        <Badge variant="outline" className={
                          entry.threat_status === 'active' ? 'text-green-400 border-green-500/30' :
                          entry.threat_status === 'emerging' ? 'text-yellow-400 border-yellow-500/30' :
                          'text-slate-400'
                        }>
                          {entry.threat_status}
                        </Badge>
                      </div>
                    </div>

                    <p className="text-slate-300 text-sm mb-3">{entry.description}</p>

                    {/* Expanded Details */}
                    <AnimatePresence>
                      {selectedEntry?.id === entry.id && (
                        <motion.div
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: 'auto' }}
                          exit={{ opacity: 0, height: 0 }}
                          className="mt-4 pt-4 border-t border-slate-700 space-y-4"
                        >
                          {/* Observed Capabilities */}
                          <div>
                            <h4 className="text-sm font-semibold text-slate-400 mb-2">Observed Capabilities</h4>
                            <div className="flex flex-wrap gap-2">
                              {entry.observed_capabilities?.map((cap, i) => (
                                <Badge key={i} variant="outline" className="text-cyan-400 border-cyan-500/30">
                                  {cap}
                                </Badge>
                              ))}
                            </div>
                          </div>

                          {/* Known Misuse Patterns */}
                          <div>
                            <h4 className="text-sm font-semibold text-slate-400 mb-2">Known Misuse Patterns</h4>
                            <ul className="list-disc list-inside text-sm text-slate-300 space-y-1">
                              {entry.known_misuse_patterns?.map((pattern, i) => (
                                <li key={i}>{pattern}</li>
                              ))}
                            </ul>
                          </div>

                          {/* Recommended Defenses */}
                          <div>
                            <h4 className="text-sm font-semibold text-slate-400 mb-2">Recommended Defenses</h4>
                            <div className="flex flex-wrap gap-2">
                              {entry.recommended_defenses?.map((defense, i) => (
                                <Badge key={i} className="bg-green-500/20 text-green-400">
                                  <Shield className="w-3 h-3 mr-1" />
                                  {defense}
                                </Badge>
                              ))}
                            </div>
                          </div>

                          {/* Metadata */}
                          <div className="text-xs text-slate-500 flex gap-4">
                            <span>First Observed: {entry.first_observed}</span>
                            <span>Last Updated: {entry.last_updated}</span>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Live AAB Evidence Tab */}
        <TabsContent value="aab-live" className="mt-4 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
            <Card style={aiIntelPanelStyle(AI_INTEL_ACCENTS.gold)}>
              <CardHeader className="pb-2">
                <CardTitle className="text-white flex items-center gap-2 text-base">
                  <Database className="w-5 h-5 text-cyan-400" />
                  38-Class Coverage
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-white">{liveAabClasses.length || 0}</div>
                <div className="text-xs text-slate-400 mt-1">
                  {aabEvidence?.class_order_ok ? 'Class order verified' : 'Waiting for latest snapshot'}
                </div>
              </CardContent>
            </Card>

            <Card style={aiIntelPanelStyle(AI_INTEL_ACCENTS.green)}>
              <CardHeader className="pb-2">
                <CardTitle className="text-white flex items-center gap-2 text-base">
                  <Shield className="w-5 h-5 text-green-400" />
                  Containment
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-white">
                  {formatCount(aabEvidence?.contained_count)} / {formatCount(aabEvidence?.run_count)}
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  {formatCount(aabEvidence?.zero_real_asset_count)} runs with zero real assets reached
                </div>
              </CardContent>
            </Card>

            <Card style={aiIntelPanelStyle(AI_INTEL_ACCENTS.magenta)}>
              <CardHeader className="pb-2">
                <CardTitle className="text-white flex items-center gap-2 text-base">
                  <Gauge className="w-5 h-5 text-purple-400" />
                  Agenticity
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-white">
                  {formatPercent(aabEvidence?.agenticity?.avg_max_score)}
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  Avg max score; peak {formatPercent(aabEvidence?.agenticity?.max_max_score)}
                </div>
              </CardContent>
            </Card>

            <Card style={aiIntelPanelStyle(AI_INTEL_ACCENTS.violet)}>
              <CardHeader className="pb-2">
                <CardTitle className="text-white flex items-center gap-2 text-base">
                  <Clock className="w-5 h-5 text-yellow-400" />
                  Latest Session
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-lg font-bold text-white">
                  {formatAabTimestamp(aabEvidence?.latest_generated_at)}
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  Claude baseline AAB rev13
                </div>
              </CardContent>
            </Card>
          </div>

          <Card style={aiIntelPanelStyle(AI_INTEL_ACCENTS.violet)}>
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <BarChart3 className="w-5 h-5 text-purple-400" />
                Agenticity Score Distribution
              </CardTitle>
              <CardDescription>
                Extracted from canonical router and detection-event score fields in the latest AAB evidence bundle
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                {[
                  ['autonomous_agent_high', 'High autonomous'],
                  ['autonomous_agent_medium', 'Medium autonomous'],
                  ['automation_suspected', 'Automation suspected'],
                  ['human_or_script_low', 'Low / script-like'],
                ].map(([key, label]) => (
                  <div key={key} className={`p-3 rounded-lg border ${getAgenticityColor(key)}`}>
                    <div className="text-2xl font-bold">{agenticityCounts[key] || 0}</div>
                    <div className="text-xs uppercase tracking-wide">{label}</div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card style={aiIntelPanelStyle(AI_INTEL_ACCENTS.gold)}>
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Terminal className="w-5 h-5 text-cyan-400" />
                Latest Live Sessions ({liveAabSessions.length})
              </CardTitle>
              <CardDescription>
                Recent AAB runs now visible on the AI activity surface
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {liveAabSessions.slice(0, 12).map((session) => (
                  <div key={`${session.aatr_id}-${session.session_id}`} className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-white font-semibold">{session.display_name}</span>
                          <Badge variant="outline" className="text-xs">{session.aatr_id}</Badge>
                          <Badge className={getAgenticityColor(session.agenticity_classification)}>
                            {formatPercent(session.max_agenticity_score)}
                          </Badge>
                        </div>
                        <div className="text-xs text-slate-400 mt-1">
                          {session.session_id} · {formatAabTimestamp(session.generated_at)}
                        </div>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <Badge className={session.contained ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}>
                          {session.contained ? 'contained' : 'escaped'}
                        </Badge>
                        <Badge variant="outline" className="text-cyan-400 border-cyan-500/30">
                          {formatCount(session.tokens)} tokens
                        </Badge>
                        <Badge variant="outline" className="text-yellow-400 border-yellow-500/30">
                          CDI {(Number(session.cdi || 0) * 100).toFixed(0)}%
                        </Badge>
                      </div>
                    </div>
                  </div>
                ))}
                {liveAabSessions.length === 0 && (
                  <div className="text-center py-10 text-slate-400">
                    <Radio className="w-12 h-12 mx-auto mb-3 opacity-50" />
                    <p>No live AAB snapshot has been loaded yet.</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          <Card style={aiIntelPanelStyle(AI_INTEL_ACCENTS.magenta)}>
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <BookOpen className="w-5 h-5 text-pink-400" />
                Live AATR Class Matrix
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                {liveAabClasses.map((entry) => (
                  <div key={`${entry.aatr_id}-${entry.class_name}`} className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                    <div className="flex items-center justify-between gap-2 mb-2">
                      <div className="min-w-0">
                        <div className="text-white font-semibold truncate">{entry.display_name}</div>
                        <div className="text-xs text-slate-500">{entry.aatr_id}</div>
                      </div>
                      <Badge className={getAgenticityColor(entry.agenticity_classification)}>
                        {formatPercent(entry.max_agenticity_score)}
                      </Badge>
                    </div>
                    <div className="grid grid-cols-3 gap-2 text-xs text-slate-400">
                      <div>
                        <div className="text-slate-500">Outcome</div>
                        <div className="text-slate-200">{entry.outcome}</div>
                      </div>
                      <div>
                        <div className="text-slate-500">Routes</div>
                        <div className="text-slate-200">
                          {(entry.routes?.trap_sink || 0) + (entry.routes?.disinformation || 0)}
                        </div>
                      </div>
                      <div>
                        <div className="text-slate-500">SOAR</div>
                        <div className="text-slate-200">{entry.soar_events || 0}</div>
                      </div>
                    </div>
                    {entry.categories?.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-3">
                        {entry.categories.slice(0, 4).map((category) => (
                          <span key={category} className="px-2 py-1 rounded bg-slate-900/60 text-slate-300 text-xs">
                            {category.replace('_', ' ')}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Detection Indicators Tab */}
        <TabsContent value="indicators" className="mt-4">
          <Card style={aiIntelPanelStyle(AI_INTEL_ACCENTS.violet)}>
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Crosshair className="w-5 h-5 text-yellow-400" />
                Defensive Detection Indicators ({indicators.length})
              </CardTitle>
              <CardDescription>
                Behavioral markers for identifying autonomous AI agents
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {['timing', 'behavior', 'syntax', 'tool_usage'].map(category => {
                  const categoryIndicators = indicators.filter(i => i.category === category);
                  if (categoryIndicators.length === 0) return null;
                  
                  return (
                    <div key={category} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                      <h3 className="text-white font-semibold mb-3 capitalize flex items-center gap-2">
                        {category === 'timing' && <Timer className="w-4 h-4 text-blue-400" />}
                        {category === 'behavior' && <Activity className="w-4 h-4 text-purple-400" />}
                        {category === 'syntax' && <Terminal className="w-4 h-4 text-green-400" />}
                        {category === 'tool_usage' && <Cpu className="w-4 h-4 text-orange-400" />}
                        {category.replace('_', ' ')} Indicators
                      </h3>
                      <div className="space-y-2">
                        {categoryIndicators.map((indicator, i) => (
                          <div key={i} className="p-2 bg-slate-900/50 rounded text-sm">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-slate-300 font-mono text-xs">
                                {indicator.indicator}
                              </span>
                              <Badge variant="outline" className="text-xs">
                                {(indicator.confidence * 100).toFixed(0)}%
                              </Badge>
                            </div>
                            <p className="text-slate-500 text-xs">{indicator.description}</p>
                            <div className="text-xs text-slate-600 mt-1">
                              From: {indicator.threat_name}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AIThreatIntelligence;
