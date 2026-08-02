import { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Badge } from "../components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { useAuth } from "../context/AuthContext";
import { toast } from "sonner";
import {
  Brain,
  Network,
  Shield,
  Key,
  Cpu,
  Database,
  Activity,
  Zap,
  Lock,
  Search,
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCw,
  Settings,
  Terminal,
  Eye,
  MessageSquare,
  Gavel,
  Orbit,
  Radar,
  Fingerprint
} from "lucide-react";

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || "").trim();
const API_URL = (!envBackendUrl || envBackendUrl.includes("localhost")) ? "/api" : `${envBackendUrl}/api`;

const ADVANCED_TONES = {
  cyan: {
    rgb: '255, 43, 214',
    text: '#ffd1f8',
    value: '#ff9ff0',
    icon: 'text-pink-400',
    iconBg: 'bg-pink-500/20',
    border: 'rgba(255,43,214,0.46)',
    glow: 'rgba(255,43,214,0.24)',
    bg: 'rgba(255,43,214,0.08)',
    alt: 'rgba(255,138,0,0.64)',
  },
  purple: {
    rgb: '188, 19, 254',
    text: '#f0d2ff',
    value: '#d6a8ff',
    icon: 'text-purple-400',
    iconBg: 'bg-purple-500/20',
    border: 'rgba(188,19,254,0.44)',
    glow: 'rgba(188,19,254,0.26)',
    bg: 'rgba(188,19,254,0.09)',
    alt: 'rgba(0,240,255,0.64)',
  },
  green: {
    rgb: '57, 255, 20',
    text: '#b8ffca',
    value: '#88ffb0',
    icon: 'text-green-400',
    iconBg: 'bg-green-500/20',
    border: 'rgba(57,255,20,0.42)',
    glow: 'rgba(57,255,20,0.24)',
    bg: 'rgba(57,255,20,0.08)',
    alt: 'rgba(0,240,255,0.58)',
  },
  gold: {
    rgb: '255, 138, 0',
    text: '#ffd78a',
    value: '#ffb020',
    icon: 'text-orange-400',
    iconBg: 'bg-orange-500/20',
    border: 'rgba(255,138,0,0.48)',
    glow: 'rgba(255,138,0,0.28)',
    bg: 'rgba(255,138,0,0.09)',
    alt: 'rgba(0,240,255,0.64)',
  },
  magenta: {
    rgb: '255, 43, 214',
    text: '#ffd1f8',
    value: '#ff9ff0',
    icon: 'text-pink-400',
    iconBg: 'bg-pink-500/20',
    border: 'rgba(255,43,214,0.46)',
    glow: 'rgba(255,43,214,0.28)',
    bg: 'rgba(255,43,214,0.09)',
    alt: 'rgba(188,19,254,0.64)',
  },
};

const advancedPanelStyle = (toneName = 'cyan') => {
  const tone = ADVANCED_TONES[toneName] || ADVANCED_TONES.cyan;
  return {
    '--sophia-hud-color': tone.border,
    '--sophia-hud-color-alt': tone.alt,
    '--advanced-rgb': tone.rgb,
    '--advanced-accent': tone.value,
    '--advanced-accent-glow': tone.glow,
    '--advanced-border': tone.border,
    border: `3px solid ${tone.border}`,
    background: `
      linear-gradient(rgba(0,0,0,0) 50%, rgba(0,0,0,0.28) 50%),
      linear-gradient(90deg, rgba(255,43,214,0.04), rgba(0,240,255,0.065), rgba(57,255,20,0.035)),
      linear-gradient(160deg, ${tone.bg}, rgba(6,14,24,0.90))
    `,
    backgroundSize: '100% 3px, 100% 100%, 100% 100%',
    boxShadow: `0 0 24px ${tone.glow}, inset 0 0 22px ${tone.bg}`,
    clipPath: 'polygon(12px 0, 100% 0, 100% calc(100% - 12px), calc(100% - 12px) 100%, 0 100%, 0 12px)',
  };
};

function AdvancedStatCard({ icon: Icon, label, value, sub, tone = 'cyan', testId }) {
  const palette = ADVANCED_TONES[tone] || ADVANCED_TONES.cyan;
  return (
    <Card
      className="sophia-card-glow sophia-panel-glow advanced-service-card"
      style={advancedPanelStyle(tone)}
      data-testid={testId}
    >
      <CardContent className="pt-6">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0">
            <p className="sophia-scan sophia-terminal-label text-sm" style={{ color: palette.text }}>{label}</p>
            <p
              className="sophia-flicker sophia-terminal-value text-2xl font-bold"
              style={{ color: palette.value, textShadow: `0 0 16px ${palette.glow}` }}
            >
              {value}
            </p>
          </div>
          <div className={`p-2 rounded-lg ${palette.iconBg}`}>
            <Icon className={`w-8 h-8 ${palette.icon}`} style={{ filter: `drop-shadow(0 0 7px ${palette.glow})` }} />
          </div>
        </div>
        {sub ? <p className="sophia-terminal-meta text-xs mt-2">{sub}</p> : null}
      </CardContent>
    </Card>
  );
}

export default function AdvancedServicesPage() {
  const { user, token } = useAuth();
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("overview");
  
  // MCP State
  const [mcpTools, setMcpTools] = useState([]);
  const [mcpExecutions, setMcpExecutions] = useState([]);
  
  // Vector Memory State
  const [memoryQuery, setMemoryQuery] = useState("");
  const [memoryResults, setMemoryResults] = useState([]);
  const [searchingMemory, setSearchingMemory] = useState(false);
  
  // VNS State (Virtual Network Sensor — live Zeek-derived telemetry)
  const [vnsFlows, setVnsFlows] = useState([]);
  const [vnsBeacons, setVnsBeacons] = useState([]);
  const [vnsDns, setVnsDns] = useState([]);
  const [vnsStats, setVnsStats] = useState(null);
  const [vnsCanaryIp, setVnsCanaryIp] = useState('');
  const [vnsCanaryDomain, setVnsCanaryDomain] = useState('');
  
  // AI State
  const [aiQuery, setAiQuery] = useState("");
  const [aiResponse, setAiResponse] = useState(null);
  const [analyzeData, setAnalyzeData] = useState({ title: "", description: "", command_line: "" });
  const [aiAnalysis, setAiAnalysis] = useState(null);
  
  // Ollama State
  const [ollamaConfig, setOllamaConfig] = useState({ base_url: "http://host.docker.internal:11434", model: "mistral" });
  
  // Quantum State
  const [quantumKeypairs, setQuantumKeypairs] = useState([]);

  const routeMix = dashboard?.deception?.route_mix || {};
  const trustEntries = Object.entries(dashboard?.world?.trust || {});
  const dominantRoute = Object.entries(routeMix).sort((a, b) => b[1] - a[1])[0]?.[0] || "none";

  useEffect(() => {
    fetchDashboard();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Auto-load VNS data when the VNS tab activates and refresh every 15s
  useEffect(() => {
    if (activeTab !== 'vns') return undefined;
    fetchVNSAll();
    const id = setInterval(fetchVNSAll, 15000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  const fetchDashboard = async () => {
    try {
      const response = await fetch(`${API_URL}/advanced/dashboard`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      setDashboard(data);
    } catch (error) {
      toast.error("Failed to fetch dashboard");
    } finally {
      setLoading(false);
    }
  };

  const fetchMCPTools = async () => {
    try {
      const response = await fetch(`${API_URL}/advanced/mcp/tools`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      setMcpTools(data.tools || []);
    } catch (error) {
      toast.error("Failed to fetch MCP tools");
    }
  };

  const searchMemory = async () => {
    if (!memoryQuery.trim()) return;
    setSearchingMemory(true);
    try {
      const response = await fetch(`${API_URL}/advanced/memory/search`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ query: memoryQuery, top_k: 10 })
      });
      const data = await response.json();
      setMemoryResults(data.results || []);
    } catch (error) {
      toast.error("Search failed");
    } finally {
      setSearchingMemory(false);
    }
  };

  const fetchVNSFlows = async () => {
    try {
      const response = await fetch(`${API_URL}/advanced/vns/flows?suspicious_only=true&limit=20`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      setVnsFlows(data.flows || []);
    } catch (error) {
      toast.error("Failed to fetch VNS flows");
    }
  };

  const fetchVNSBeacons = async () => {
    try {
      const response = await fetch(`${API_URL}/advanced/vns/beacons`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      setVnsBeacons(data.beacons || []);
    } catch (error) {
      toast.error("Failed to fetch beacons");
    }
  };

  const fetchVNSDns = async () => {
    try {
      const response = await fetch(`${API_URL}/advanced/vns/dns?limit=30`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      setVnsDns(data.queries || data.dns_queries || []);
    } catch (error) {
      // Silent — DNS endpoint may have no data yet on a cold start.
    }
  };

  const fetchVNSStats = async () => {
    try {
      const response = await fetch(`${API_URL}/advanced/vns/stats`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (!response.ok) return;
      const data = await response.json();
      setVnsStats(data);
    } catch (error) {
      // VNS may not be enabled in this build — fail silently.
    }
  };

  const fetchVNSAll = async () => {
    await Promise.all([fetchVNSFlows(), fetchVNSBeacons(), fetchVNSDns(), fetchVNSStats()]);
  };

  const addCanaryIp = async () => {
    const ip = vnsCanaryIp.trim();
    if (!ip) return;
    try {
      const response = await fetch(
        `${API_URL}/advanced/vns/canary/ip?ip=${encodeURIComponent(ip)}`,
        { method: 'POST', headers: { Authorization: `Bearer ${token}` } },
      );
      if (!response.ok) throw new Error(await response.text());
      toast.success(`Canary IP ${ip} armed`);
      setVnsCanaryIp('');
      fetchVNSStats();
    } catch (error) {
      toast.error('Failed to register canary IP');
    }
  };

  const addCanaryDomain = async () => {
    const domain = vnsCanaryDomain.trim();
    if (!domain) return;
    try {
      const response = await fetch(
        `${API_URL}/advanced/vns/canary/domain?domain=${encodeURIComponent(domain)}`,
        { method: 'POST', headers: { Authorization: `Bearer ${token}` } },
      );
      if (!response.ok) throw new Error(await response.text());
      toast.success(`Canary domain ${domain} armed`);
      setVnsCanaryDomain('');
      fetchVNSStats();
    } catch (error) {
      toast.error('Failed to register canary domain');
    }
  };

  const queryAI = async () => {
    if (!aiQuery.trim()) return;
    try {
      const response = await fetch(`${API_URL}/advanced/ai/query`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ question: aiQuery })
      });
      const data = await response.json();
      setAiResponse(data);
    } catch (error) {
      toast.error("AI query failed");
    }
  };

  const analyzeThreat = async () => {
    if (!analyzeData.title.trim()) return;
    try {
      const response = await fetch(`${API_URL}/advanced/ai/analyze`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(analyzeData)
      });
      const data = await response.json();
      setAiAnalysis(data);
      toast.success("Threat analyzed");
    } catch (error) {
      toast.error("Analysis failed");
    }
  };

  const configureOllama = async () => {
    try {
      const response = await fetch(`${API_URL}/advanced/ai/ollama/configure`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(ollamaConfig)
      });
      const data = await response.json();
      if (data.status === "connected") {
        toast.success(`Connected to Ollama! Models: ${data.available_models?.join(", ")}`);
      } else {
        toast.warning(data.note || data.error);
      }
      fetchDashboard();
    } catch (error) {
      toast.error("Failed to configure Ollama");
    }
  };

  const generateQuantumKey = async (algorithm) => {
    try {
      const endpoint = algorithm === "kyber"
        ? `${API_URL}/advanced/quantum/keypair/kyber`
        : `${API_URL}/advanced/quantum/keypair/dilithium`;
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      toast.success(`Generated ${algorithm.toUpperCase()} keypair: ${data.key_id}`);
      fetchDashboard();
    } catch (error) {
      toast.error("Key generation failed");
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="sophia-scan sophia-terminal-label text-cyan-200 animate-pulse">Loading Advanced Services...</div>
      </div>
    );
  }

  return (
    <div className="advanced-services-page space-y-6 p-6 sophia-isolated" data-testid="advanced-services-page">
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="space-y-1">
          <p className="sophia-scan text-xs uppercase tracking-[0.34em] advanced-services-eyebrow">
            sophia · advanced · governed services
          </p>
          <h1
            className="seraph-heading-raw m-0"
            style={{
              fontFamily: "'SDGlitch', 'Orbitron', sans-serif",
              fontWeight: 900,
              fontSize: 'clamp(2rem, 4vw, 3rem)',
              letterSpacing: '0.08em',
              lineHeight: 1,
              textTransform: 'uppercase',
              textShadow: '0 0 14px rgba(255,43,214,0.28)',
            }}
          >
            <span className="seraph-heading-flood-rtl">Advanced Security Services</span>
          </h1>
          <p className="panel-subtext text-sm advanced-services-tagline">
            {'> governed tool bus · vector memory · VNS telemetry · quantum controls · local reasoning'}
          </p>
        </div>
        <Button className="sophia-btn sophia-btn-refresh" onClick={fetchDashboard} variant="outline" size="sm" style={{ borderColor: 'rgba(255,43,214,0.54)', color: '#ffb5f4' }}>
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <AdvancedStatCard
          icon={Terminal}
          label="MCP Tools"
          value={dashboard?.mcp?.tools_registered || 0}
          sub={`${dashboard?.mcp?.total_executions || 0} executions`}
          tone="magenta"
          testId="mcp-card"
        />

        <AdvancedStatCard
          icon={Database}
          label="Vector Memory"
          value={dashboard?.memory?.total_entries || 0}
          sub={`${dashboard?.memory?.total_cases || 0} cases`}
          tone="purple"
          testId="memory-card"
        />

        <AdvancedStatCard
          icon={Network}
          label="VNS Flows"
          value={dashboard?.vns?.total_flows || 0}
          sub={`${dashboard?.vns?.suspicious_flows || 0} suspicious`}
          tone="green"
          testId="vns-card"
        />

        <AdvancedStatCard
          icon={Radar}
          label="Deception Events"
          value={dashboard?.deception?.recent_events || 0}
          sub={`${dashboard?.deception?.active_campaigns || 0} campaigns`}
          tone="cyan"
          testId="deception-card"
        />

        <AdvancedStatCard
          icon={Gavel}
          label="Governance Queue"
          value={dashboard?.governance?.pending_decisions || 0}
          sub={`${dashboard?.governance?.executor_ready || 0} executor-ready`}
          tone="magenta"
          testId="governance-card"
        />

        <AdvancedStatCard
          icon={Orbit}
          label="World Risk"
          value={dashboard?.world?.risk_level || "unknown"}
          sub={`${dashboard?.world?.triune_analyses || 0} triune analyses`}
          tone="purple"
          testId="world-card"
        />

        <AdvancedStatCard
          icon={Key}
          label="Quantum Keys"
          value={dashboard?.quantum?.keypairs?.total || 0}
          sub={dashboard?.quantum?.mode || "simulation"}
          tone="gold"
          testId="quantum-card"
        />

        <Card
          className="sophia-card-glow sophia-panel-glow advanced-service-card"
          style={advancedPanelStyle('magenta')}
          data-testid="ai-card"
        >
          <CardContent className="pt-6">
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <p className="sophia-scan sophia-terminal-label text-sm" style={{ color: ADVANCED_TONES.magenta.text }}>AI Analyses</p>
                <p
                  className="sophia-flicker sophia-terminal-value text-2xl font-bold"
                  style={{ color: ADVANCED_TONES.magenta.value, textShadow: `0 0 16px ${ADVANCED_TONES.magenta.glow}` }}
                >
                  {dashboard?.ai?.analyses_performed || 0}
                </p>
              </div>
              <div className="p-2 rounded-lg bg-pink-500/20">
                <Brain className="w-8 h-8 text-pink-400" style={{ filter: `drop-shadow(0 0 7px ${ADVANCED_TONES.magenta.glow})` }} />
              </div>
            </div>
            <Badge 
              variant={dashboard?.ai?.ollama?.status === "connected" ? "success" : "secondary"}
              className="mt-2 sophia-badge-pulse"
            >
              {dashboard?.ai?.ollama?.status || "disconnected"}
            </Badge>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="advanced-services-tabs bg-slate-900/50 border border-slate-800">
          <TabsTrigger value="overview" data-testid="tab-overview" className="advanced-tab advanced-tab--overview">
            <Activity className="w-4 h-4 mr-2" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="mcp" data-testid="tab-mcp" className="advanced-tab advanced-tab--mcp">
            <Terminal className="w-4 h-4 mr-2" />
            MCP Server
          </TabsTrigger>
          <TabsTrigger value="memory" data-testid="tab-memory" className="advanced-tab advanced-tab--memory">
            <Database className="w-4 h-4 mr-2" />
            Vector Memory
          </TabsTrigger>
          <TabsTrigger value="vns" data-testid="tab-vns" className="advanced-tab advanced-tab--vns">
            <Network className="w-4 h-4 mr-2" />
            VNS
          </TabsTrigger>
          <TabsTrigger value="quantum" data-testid="tab-quantum" className="advanced-tab advanced-tab--quantum">
            <Key className="w-4 h-4 mr-2" />
            Quantum
          </TabsTrigger>
          <TabsTrigger value="ai" data-testid="tab-ai" className="advanced-tab advanced-tab--ai">
            <Brain className="w-4 h-4 mr-2" />
            AI Reasoning
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
            <Card className="advanced-overview-card bg-slate-900/50 border-slate-800 xl:col-span-3">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Shield className="w-5 h-5 text-cyan-400" />
                  Canonical Runtime Chain
                </CardTitle>
                <CardDescription>Port 3000 now tracks the hardened backend path instead of legacy-only service islands</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-5 gap-3 text-sm">
                  <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700">
                    <p className="text-slate-400 mb-1">Deception</p>
                    <p className="text-cyan-300 font-semibold">{dashboard?.deception?.status || "unknown"}</p>
                    <p className="text-xs text-slate-500 mt-1">dominant route: {dominantRoute.replaceAll("_", " ")}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700">
                    <p className="text-slate-400 mb-1">Harmonic / Governance</p>
                    <p className="text-pink-300 font-semibold">{dashboard?.governance?.harmonic_review_required || 0} reviews</p>
                    <p className="text-xs text-slate-500 mt-1">{dashboard?.governance?.notation_narrowed || 0} notation narrowings</p>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700">
                    <p className="text-slate-400 mb-1">World State</p>
                    <p className="text-purple-300 font-semibold">{dashboard?.world?.risk_level || "unknown"}</p>
                    <p className="text-xs text-slate-500 mt-1">{dashboard?.world?.world_state_hash ? "manifold bound" : "hash unavailable"}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700">
                    <p className="text-slate-400 mb-1">VNS Pulse</p>
                    <p className="text-green-300 font-semibold">{dashboard?.governance?.pulse_events || 0} pulse events</p>
                    <p className="text-xs text-slate-500 mt-1">{dashboard?.vns?.beacon_detections || 0} beacons detected</p>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700">
                    <p className="text-slate-400 mb-1">Dispatch / MCP</p>
                    <p className="text-amber-300 font-semibold">{dashboard?.mcp?.pending_requests || 0} pending requests</p>
                    <p className="text-xs text-slate-500 mt-1">{dashboard?.governance?.executor_ready || 0} awaiting execution</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* MCP Status */}
            <Card className="advanced-overview-card advanced-overview-card--mcp bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-cyan-400" />
                  Model Context Protocol (MCP)
                </CardTitle>
                <CardDescription>Governed tool bus for agent operations</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Tools Registered</span>
                    <span className="text-white">{dashboard?.mcp?.tools_registered}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Pending Requests</span>
                    <span className="text-white">{dashboard?.mcp?.pending_requests}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Total Executions</span>
                    <span className="text-white">{dashboard?.mcp?.total_executions}</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* VNS Status */}
            <Card className="advanced-overview-card advanced-overview-card--vns bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Network className="w-5 h-5 text-green-400" />
                  Virtual Network Sensor (VNS)
                </CardTitle>
                <CardDescription>Independent network truth source</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Total Flows</span>
                    <span className="text-white">{dashboard?.vns?.total_flows}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Suspicious DNS</span>
                    <span className="text-red-400">{dashboard?.vns?.suspicious_dns}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Beacon Detections</span>
                    <span className="text-orange-400">{dashboard?.vns?.beacon_detections}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">TLS Fingerprints</span>
                    <span className="text-white">{dashboard?.vns?.tls_fingerprints}</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="advanced-overview-card bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Gavel className="w-5 h-5 text-pink-400" />
                  Harmonic Governance
                </CardTitle>
                <CardDescription>Approval, notation, world-state binding, and executor readiness</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Pending Decisions</span>
                    <span className="text-white">{dashboard?.governance?.pending_decisions || 0}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Harmonic Reviews</span>
                    <span className="text-pink-300">{dashboard?.governance?.harmonic_review_required || 0}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">World Drift Holds</span>
                    <span className="text-red-300">{dashboard?.governance?.world_state_mismatches || 0}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Notation Narrowed</span>
                    <span className="text-orange-300">{dashboard?.governance?.notation_narrowed || 0}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Executor Ready</span>
                    <span className="text-green-300">{dashboard?.governance?.executor_ready || 0}</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="advanced-overview-card bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Orbit className="w-5 h-5 text-purple-400" />
                  World State and Triune
                </CardTitle>
                <CardDescription>Manifold-backed risk and bounded triune reasoning posture</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Risk Level</span>
                    <Badge variant="outline">{dashboard?.world?.risk_level || "unknown"}</Badge>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Triune Analyses</span>
                    <span className="text-white">{dashboard?.world?.triune_analyses || 0}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Campaigns</span>
                    <span className="text-white">{dashboard?.world?.active_campaigns || 0}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Hotspots</span>
                    <span className="text-red-300">{dashboard?.world?.hotspots || 0}</span>
                  </div>
                  <div className="text-xs text-slate-500 mt-2">
                    {dashboard?.world?.world_state_hash ? `hash ${String(dashboard.world.world_state_hash).slice(0, 18)}...` : "world manifold hash unavailable"}
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="advanced-overview-card bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Fingerprint className="w-5 h-5 text-cyan-400" />
                  Deception Runtime
                </CardTitle>
                <CardDescription>Live route shaping, campaign pressure, and disinformation containment</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Campaigns</span>
                    <span className="text-white">{dashboard?.deception?.active_campaigns || 0}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Recent Events</span>
                    <span className="text-white">{dashboard?.deception?.recent_events || 0}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Trap Hits</span>
                    <span className="text-red-300">{dashboard?.deception?.trap_hits || 0}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Disinformation Sessions</span>
                    <span className="text-blue-300">{dashboard?.deception?.disinformation_sessions || 0}</span>
                  </div>
                  <div className="text-xs text-slate-500 mt-2">
                    dominant route: {dominantRoute.replaceAll("_", " ")}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Quantum Status */}
            <Card className="advanced-overview-card advanced-overview-card--quantum bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Shield className="w-5 h-5 text-yellow-400" />
                  Quantum Security
                </CardTitle>
                <CardDescription>Post-quantum cryptography</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Mode</span>
                    <Badge variant="outline">{dashboard?.quantum?.mode}</Badge>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Kyber Keys</span>
                    <span className="text-white">{dashboard?.quantum?.keypairs?.kyber}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Dilithium Keys</span>
                    <span className="text-white">{dashboard?.quantum?.keypairs?.dilithium}</span>
                  </div>
                  <div className="text-xs text-slate-500 mt-2">
                    Algorithms: {dashboard?.quantum?.algorithms?.kem?.join(", ")}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* AI Status */}
            <Card className="advanced-overview-card advanced-overview-card--ai bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Brain className="w-5 h-5 text-pink-400" />
                  AI Reasoning Engine
                </CardTitle>
                <CardDescription>Local threat analysis with Ollama</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">MITRE Techniques</span>
                    <span className="text-white">{dashboard?.ai?.mitre_techniques_loaded}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Threat Patterns</span>
                    <span className="text-white">{dashboard?.ai?.threat_patterns_loaded}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Ollama</span>
                    <Badge variant={dashboard?.ai?.ollama?.status === "connected" ? "success" : "secondary"}>
                      {dashboard?.ai?.ollama?.status}
                    </Badge>
                  </div>
                  <div className="text-xs text-slate-500 mt-2">
                    {dashboard?.ai?.ollama?.note}
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="advanced-overview-card bg-slate-900/50 border-slate-800 xl:col-span-3">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <MessageSquare className="w-5 h-5 text-cyan-400" />
                  Trust and Pending Decisions
                </CardTitle>
                <CardDescription>High-signal cross-links from the world graph into governance execution</CardDescription>
              </CardHeader>
              <CardContent className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <p className="text-sm text-slate-400">Trust dimensions</p>
                  {trustEntries.length ? trustEntries.map(([key, value]) => (
                    <div key={key} className="flex justify-between text-sm border-b border-slate-800 pb-2">
                      <span className="text-slate-500">{key.replaceAll("_", " ")}</span>
                      <span className="text-white">{String(value)}</span>
                    </div>
                  )) : <p className="text-sm text-slate-500">No trust dimensions published yet.</p>}
                </div>
                <div className="space-y-2">
                  <p className="text-sm text-slate-400">Pending governance items</p>
                  {(dashboard?.governance?.recent_pending || []).length ? (dashboard.governance.recent_pending || []).map((item) => (
                    <div key={item.decision_id} className="rounded-lg border border-slate-800 bg-slate-800/40 p-3">
                      <div className="flex items-center justify-between gap-3 text-sm">
                        <span className="text-white">{item.decision_type || "decision"}</span>
                        <Badge variant="outline">{item.decision_id}</Badge>
                      </div>
                      <p className="text-xs text-slate-500 mt-2">{item.created_at || "timestamp unavailable"}</p>
                    </div>
                  )) : <p className="text-sm text-slate-500">No pending governance decisions.</p>}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* MCP Tab */}
        <TabsContent value="mcp" className="space-y-4">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-white">MCP Tool Registry</CardTitle>
                <Button onClick={fetchMCPTools} variant="outline" size="sm">
                  <RefreshCw className="w-4 h-4 mr-2" />
                  Load Tools
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {mcpTools.length === 0 ? (
                <p className="text-slate-400 text-center py-4">Click "Load Tools" to view available MCP tools</p>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {mcpTools.map((tool) => (
                    <div key={tool.tool_id} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                      <div className="flex items-center gap-2 mb-2">
                        <Terminal className="w-4 h-4 text-cyan-400" />
                        <span className="font-medium text-white">{tool.name}</span>
                      </div>
                      <p className="text-sm text-slate-400 mb-2">{tool.description}</p>
                      <div className="flex gap-2">
                        <Badge variant="outline">{tool.category}</Badge>
                        <Badge variant="secondary">v{tool.version}</Badge>
                      </div>
                      <div className="mt-2 text-xs text-slate-500">
                        Trust: {tool.required_trust_state} | Rate: {tool.rate_limit}/hr
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Vector Memory Tab */}
        <TabsContent value="memory" className="space-y-4">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Semantic Memory Search</CardTitle>
              <CardDescription>Search incident cases and threat intel by meaning</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex gap-2 mb-4">
                <Input
                  placeholder="Search for threats, incidents, IOCs..."
                  value={memoryQuery}
                  onChange={(e) => setMemoryQuery(e.target.value)}
                  onKeyPress={(e) => e.key === "Enter" && searchMemory()}
                  className="bg-slate-800 border-slate-700"
                  data-testid="memory-search-input"
                />
                <Button onClick={searchMemory} disabled={searchingMemory}>
                  <Search className="w-4 h-4 mr-2" />
                  {searchingMemory ? "Searching..." : "Search"}
                </Button>
              </div>
              {memoryResults.length > 0 && (
                <div className="space-y-2">
                  {memoryResults.map((result) => (
                    <div key={result.entry_id} className="p-3 bg-slate-800/50 rounded border border-slate-700">
                      <div className="flex items-center justify-between mb-1">
                        <Badge variant="outline">{result.namespace}</Badge>
                        <span className="text-xs text-slate-400">
                          Similarity: {(result.similarity * 100).toFixed(1)}%
                        </span>
                      </div>
                      <p className="text-sm text-slate-300">{result.content}</p>
                      <div className="flex gap-2 mt-2">
                        <Badge variant="secondary">{result.trust_level}</Badge>
                        <span className="text-xs text-slate-500">
                          Confidence: {(result.confidence * 100).toFixed(0)}%
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Memory Statistics</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-purple-400">{dashboard?.memory?.total_entries || 0}</p>
                  <p className="text-sm text-slate-400">Total Entries</p>
                </div>
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-blue-400">{dashboard?.memory?.total_cases || 0}</p>
                  <p className="text-sm text-slate-400">Incident Cases</p>
                </div>
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-red-400">{dashboard?.memory?.total_intel || 0}</p>
                  <p className="text-sm text-slate-400">Threat Intel</p>
                </div>
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-cyan-400">{dashboard?.memory?.embedding_dimension || 128}</p>
                  <p className="text-sm text-slate-400">Embedding Dim</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* VNS Tab */}
        <TabsContent value="vns" className="space-y-4">
          {/* === Animated Flow Map === */}
          <div
            className="seraph-corner-brackets relative p-5 overflow-hidden"
            style={{
              background:
                'radial-gradient(circle at 20% 50%, rgba(255,43,214,0.08), transparent 40%), radial-gradient(circle at 80% 50%, rgba(255,138,0,0.08), transparent 40%), linear-gradient(160deg, rgba(24,9,38,0.86), rgba(2,8,19,0.92))',
              border: '3px solid rgba(255,43,214,0.62)',
              boxShadow: 'inset 0 0 16px rgba(255,43,214,0.06), 0 0 10px rgba(255,43,214,0.18)',
              minHeight: 280,
            }}
          >
            <span className="seraph-corner-tl" />
            <span className="seraph-corner-tr" />
            <span className="seraph-corner-bl" />
            <span className="seraph-corner-br" />

            <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
              <div className="flex items-center gap-2">
                <span className="seraph-pip" />
                <span style={{ fontFamily: "'FfMoon', 'Orbitron', monospace", fontSize: 10, letterSpacing: '0.22em', color: '#ff9ff0', textTransform: 'uppercase', textShadow: '0 0 6px rgba(255,43,214,0.36)' }}>
                  VNS · LIVE FLOW MAP
                </span>
              </div>
              <span style={{ fontFamily: "'Rajdhani', 'IBM Plex Sans', sans-serif", fontSize: 12, color: '#ffd78a', letterSpacing: '0.08em' }}>
                {vnsFlows.length} ACTIVE / {vnsBeacons.length} BEACONS
              </span>
            </div>

            {/* SVG flow diagram */}
            <svg viewBox="0 0 800 200" preserveAspectRatio="none" style={{ width: '100%', height: 200 }}>
              <defs>
                <linearGradient id="vns-arc" x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stopColor="rgba(255,43,214,0.0)" />
                  <stop offset="40%" stopColor="rgba(255,43,214,0.7)" />
                  <stop offset="60%" stopColor="rgba(255,138,0,0.7)" />
                  <stop offset="100%" stopColor="rgba(255,43,214,0.0)" />
                </linearGradient>
                <linearGradient id="vns-arc-bad" x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stopColor="rgba(255,56,56,0.0)" />
                  <stop offset="50%" stopColor="rgba(255,56,56,0.85)" />
                  <stop offset="100%" stopColor="rgba(255,43,214,0.0)" />
                </linearGradient>
                <radialGradient id="vns-node" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="rgba(255,43,214,1)" />
                  <stop offset="60%" stopColor="rgba(255,43,214,0.4)" />
                  <stop offset="100%" stopColor="rgba(255,43,214,0)" />
                </radialGradient>
              </defs>

              {/* Internal column */}
              {[40, 80, 120, 160].map((y, i) => (
                <g key={`int-${i}`}>
                  <circle cx={70} cy={y} r={14} fill="url(#vns-node)" />
                  <circle cx={70} cy={y} r={5} fill="#ff2bd6" filter="drop-shadow(0 0 5px #ff2bd6)" />
                  <text x={92} y={y + 4} fill="#ffd1f8" fontSize="10" fontFamily="'Rajdhani', sans-serif" letterSpacing="0.06em">
                    INT-{(i + 1).toString().padStart(2, '0')}
                  </text>
                </g>
              ))}

              {/* External column */}
              {[40, 80, 120, 160].map((y, i) => {
                const flow = vnsFlows[i];
                const isBad = !!flow;
                const fill = isBad ? '#ff3838' : '#39ff14';
                return (
                  <g key={`ext-${i}`}>
                    <circle cx={730} cy={y} r={14} fill={`url(#vns-node)`} opacity={0.9} />
                    <circle
                      cx={730}
                      cy={y}
                      r={5}
                      fill={fill}
                      filter={`drop-shadow(0 0 6px ${fill})`}
                    >
                      <animate
                        attributeName="opacity"
                        values="0.6;1;0.6"
                        dur={isBad ? '0.9s' : '2.4s'}
                        repeatCount="indefinite"
                      />
                    </circle>
                    <text x={650} y={y + 4} fill={isBad ? '#ff8a96' : '#7fffa6'} fontSize="10" fontFamily="'Rajdhani', sans-serif" letterSpacing="0.04em" textAnchor="end">
                      {flow ? `${flow.dst_ip}` : `EXT-${(i + 1).toString().padStart(2, '0')}`}
                    </text>
                  </g>
                );
              })}

              {/* Arc connections */}
              {[40, 80, 120, 160].map((y, i) => {
                const isBad = !!vnsFlows[i];
                return (
                  <path
                    key={`arc-${i}`}
                    d={`M 84 ${y} Q 400 ${y - 30 + i * 5} 716 ${y}`}
                    fill="none"
                    stroke={isBad ? 'url(#vns-arc-bad)' : 'url(#vns-arc)'}
                    strokeWidth={isBad ? 1.6 : 1.1}
                    strokeDasharray={isBad ? '6 4' : '4 8'}
                  >
                    <animate
                      attributeName="stroke-dashoffset"
                      from="0"
                      to={isBad ? '-200' : '200'}
                      dur={isBad ? '1.4s' : '4s'}
                      repeatCount="indefinite"
                    />
                  </path>
                );
              })}

              {/* Center label */}
              <text x="400" y="20" textAnchor="middle" fill="#ffd78a" fontSize="10" fontFamily="'FfMoon', 'Orbitron', monospace" letterSpacing="0.18em">
                VECTOR · NETWORK · STREAMS
              </text>
            </svg>

            <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mt-2">
              {[
                { label: 'TOTAL', val: dashboard?.vns?.total_flows || 0, c: '#ff2bd6' },
                { label: 'SUSPICIOUS', val: dashboard?.vns?.suspicious_flows || 0, c: '#ff3838' },
                { label: 'DNS', val: dashboard?.vns?.total_dns_queries || 0, c: '#ff8a00' },
                { label: 'BEACONS', val: dashboard?.vns?.beacon_detections || 0, c: '#bc13fe' },
                { label: 'TLS FP', val: dashboard?.vns?.tls_fingerprints || 0, c: '#39ff14' },
              ].map((m) => (
                <div
                  key={m.label}
                  className="text-center p-2"
                  style={{
                    background: `linear-gradient(160deg, ${m.c}10, rgba(2,8,19,0.86))`,
                    border: `1px solid ${m.c}55`,
                    boxShadow: `inset 0 0 12px ${m.c}11`,
                    clipPath: 'polygon(6px 0, 100% 0, 100% calc(100% - 6px), calc(100% - 6px) 100%, 0 100%, 0 6px)',
                  }}
                >
                  <p
                    style={{
                      fontFamily: "'Deluxe', 'Orbitron', monospace",
                      fontSize: '1.4rem',
                      fontWeight: 900,
                      color: m.c,
                      textShadow: `0 0 10px ${m.c}99`,
                      lineHeight: 1,
                    }}
                  >
                    {m.val}
                  </p>
                  <p style={{ fontFamily: "'FfMoon', 'Orbitron', monospace", fontSize: 9, color: '#d8ffdf', letterSpacing: '0.18em', marginTop: 4 }}>
                    {m.label}
                  </p>
                </div>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-white">Suspicious Flows</CardTitle>
                  <Button onClick={fetchVNSFlows} variant="outline" size="sm">
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Refresh
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                {vnsFlows.length === 0 ? (
                  <p className="text-slate-400 text-center py-4">No suspicious flows detected</p>
                ) : (
                  <div className="space-y-2 max-h-80 overflow-y-auto">
                    {vnsFlows.map((flow) => (
                      <div key={flow.flow_id} className="p-3 bg-slate-800/50 rounded border border-red-900/50">
                        <div className="flex items-center justify-between">
                          <span className="text-white font-mono text-sm">
                            {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port}
                          </span>
                          <Badge variant="destructive">{flow.threat_score}</Badge>
                        </div>
                        <div className="text-xs text-slate-400 mt-1">
                          {flow.direction} | {flow.service}
                        </div>
                        {flow.threat_indicators?.length > 0 && (
                          <div className="mt-2">
                            {flow.threat_indicators.map((ind, i) => (
                              <Badge key={i} variant="outline" className="mr-1 text-xs">{ind}</Badge>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-white">C2 Beacon Detections</CardTitle>
                  <Button onClick={fetchVNSBeacons} variant="outline" size="sm">
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Refresh
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                {vnsBeacons.length === 0 ? (
                  <p className="text-slate-400 text-center py-4">No beacons detected</p>
                ) : (
                  <div className="space-y-2 max-h-80 overflow-y-auto">
                    {vnsBeacons.map((beacon) => (
                      <div key={beacon.detection_id} className="p-3 bg-slate-800/50 rounded border border-orange-900/50">
                        <div className="flex items-center justify-between">
                          <span className="text-white font-mono text-sm">
                            {beacon.src_ip} → {beacon.dst_ip}:{beacon.dst_port}
                          </span>
                          <Badge variant={beacon.is_confirmed ? "destructive" : "secondary"}>
                            {beacon.is_confirmed ? "Confirmed" : "Suspected"}
                          </Badge>
                        </div>
                        <div className="text-xs text-slate-400 mt-1">
                          Interval: {beacon.interval_seconds?.toFixed(1)}s | Jitter: {beacon.interval_jitter?.toFixed(2)}
                        </div>
                        <div className="text-xs text-slate-500">
                          Confidence: {(beacon.confidence * 100).toFixed(0)}% | Algorithm: {beacon.algorithm}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Live VNS Statistics — refreshed every 15s from /advanced/vns/stats.
              Falls back to the dashboard payload when the live endpoint is
              cold (no flows yet). */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-white">VNS Statistics — Live</CardTitle>
                <Badge variant="outline" className="text-cyan-300 border-cyan-700">
                  {vnsStats ? 'LIVE' : 'COLD'}
                </Badge>
              </div>
              <CardDescription>
                Zeek-derived flows, DNS, beacons. Auto-refreshes every 15s while VNS tab is open.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-green-400">{vnsStats?.total_flows ?? dashboard?.vns?.total_flows ?? 0}</p>
                  <p className="text-sm text-slate-400">Total Flows</p>
                </div>
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-red-400">{vnsStats?.suspicious_flows ?? dashboard?.vns?.suspicious_flows ?? 0}</p>
                  <p className="text-sm text-slate-400">Suspicious</p>
                </div>
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-blue-400">{vnsStats?.total_dns_queries ?? dashboard?.vns?.total_dns_queries ?? 0}</p>
                  <p className="text-sm text-slate-400">DNS Queries</p>
                </div>
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-orange-400">{vnsStats?.beacon_detections ?? dashboard?.vns?.beacon_detections ?? 0}</p>
                  <p className="text-sm text-slate-400">Beacons</p>
                </div>
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-purple-400">{vnsStats?.tls_fingerprints ?? dashboard?.vns?.tls_fingerprints ?? 0}</p>
                  <p className="text-sm text-slate-400">TLS FPs</p>
                </div>
                <div className="text-center p-4 bg-slate-800/50 rounded">
                  <p className="text-2xl font-bold text-pink-400">
                    {(vnsStats?.canary_ips?.length ?? 0) +
                      (vnsStats?.canary_domains?.length ?? 0) +
                      (vnsStats?.canary_ports?.length ?? 0)}
                  </p>
                  <p className="text-sm text-slate-400">Canaries Armed</p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* DNS Queries — live Zeek dns.log replay through VNS */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-white">Recent DNS Queries</CardTitle>
                <Button onClick={fetchVNSDns} variant="outline" size="sm">
                  <RefreshCw className="w-4 h-4 mr-2" />
                  Refresh
                </Button>
              </div>
              <CardDescription>
                Live DNS lookups observed by Zeek; canary domain hits are flagged red.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {vnsDns.length === 0 ? (
                <p className="text-slate-400 text-center py-4">No DNS queries captured yet</p>
              ) : (
                <div className="space-y-2 max-h-80 overflow-y-auto">
                  {vnsDns.map((q, i) => {
                    // Backend returns: query_name / query_type / response_ips
                    // / response_code / is_suspicious / threat_indicators[]
                    const dom = q.query_name || q.query || q.qname || q.domain || '?';
                    const qtype = q.query_type || q.qtype;
                    const answers = q.response_ips || q.answers || [];
                    const flagged = !!q.is_suspicious || !!q.is_canary;
                    return (
                      <div
                        key={q.query_id || i}
                        className={`p-3 bg-slate-800/50 rounded border ${flagged ? 'border-red-700' : 'border-cyan-900/50'}`}
                      >
                        <div className="flex items-center justify-between flex-wrap gap-2">
                          <span className="font-mono text-sm">
                            <span className="text-cyan-300">{q.src_ip || q.client || '?'}</span>
                            <span className="text-slate-500"> → </span>
                            <span className="text-white">{dom}</span>
                          </span>
                          <div className="flex items-center gap-2">
                            {qtype ? (
                              <Badge variant="outline" className="text-xs text-purple-300 border-purple-700">
                                {qtype}
                              </Badge>
                            ) : null}
                            {q.response_code && q.response_code !== 'NOERROR' ? (
                              <Badge variant="outline" className="text-xs text-amber-300 border-amber-700">
                                {q.response_code}
                              </Badge>
                            ) : null}
                            {flagged ? (
                              <Badge variant="destructive" className="text-xs">
                                {q.is_canary ? 'CANARY HIT' : 'SUSPICIOUS'}
                              </Badge>
                            ) : null}
                          </div>
                        </div>
                        <div className="text-xs text-slate-400 mt-1">
                          {answers.length ? `→ ${answers.slice(0, 3).join(', ')}` : 'no answers'}
                          {q.timestamp ? ` · ${new Date(q.timestamp).toLocaleTimeString()}` : ''}
                        </div>
                        {flagged && q.threat_indicators?.length ? (
                          <div className="mt-2 flex flex-wrap gap-1">
                            {q.threat_indicators.map((ind, k) => (
                              <Badge key={k} variant="outline" className="text-xs text-red-300 border-red-700">
                                {ind}
                              </Badge>
                            ))}
                          </div>
                        ) : null}
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Canary feed management — POST /advanced/vns/canary/{ip,domain} */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Canary Management</CardTitle>
              <CardDescription>
                Arm IP / domain canaries. Any flow or DNS lookup that touches an armed canary is flagged in real-time.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm text-slate-400">Canary IP</label>
                  <div className="flex gap-2">
                    <Input
                      value={vnsCanaryIp}
                      onChange={(e) => setVnsCanaryIp(e.target.value)}
                      placeholder="10.0.0.99"
                      className="bg-slate-950 border-slate-700 text-white"
                      onKeyDown={(e) => { if (e.key === 'Enter') addCanaryIp(); }}
                    />
                    <Button onClick={addCanaryIp} className="bg-cyan-600 hover:bg-cyan-700">
                      Arm
                    </Button>
                  </div>
                </div>
                <div className="space-y-2">
                  <label className="text-sm text-slate-400">Canary Domain</label>
                  <div className="flex gap-2">
                    <Input
                      value={vnsCanaryDomain}
                      onChange={(e) => setVnsCanaryDomain(e.target.value)}
                      placeholder="totally-not-honey.local"
                      className="bg-slate-950 border-slate-700 text-white"
                      onKeyDown={(e) => { if (e.key === 'Enter') addCanaryDomain(); }}
                    />
                    <Button onClick={addCanaryDomain} className="bg-pink-600 hover:bg-pink-700">
                      Arm
                    </Button>
                  </div>
                </div>
              </div>
              {vnsStats?.canary_ips?.length || vnsStats?.canary_domains?.length ? (
                <div className="mt-4 pt-4 border-t border-slate-800 space-y-2">
                  {(vnsStats.canary_ips || []).length > 0 && (
                    <div>
                      <p className="text-xs text-slate-400 mb-1">Armed IPs:</p>
                      <div className="flex flex-wrap gap-1">
                        {vnsStats.canary_ips.map((ip) => (
                          <Badge key={ip} variant="outline" className="text-cyan-300 border-cyan-700">
                            {ip}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {(vnsStats.canary_domains || []).length > 0 && (
                    <div>
                      <p className="text-xs text-slate-400 mb-1">Armed Domains:</p>
                      <div className="flex flex-wrap gap-1">
                        {vnsStats.canary_domains.map((d) => (
                          <Badge key={d} variant="outline" className="text-pink-300 border-pink-700">
                            {d}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Quantum Tab */}
        <TabsContent value="quantum" className="space-y-4">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Quantum Key Generation</CardTitle>
              <CardDescription>Generate post-quantum cryptographic keys</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 bg-slate-800/50 rounded border border-slate-700">
                  <h3 className="font-medium text-white mb-2">KYBER (Key Encapsulation)</h3>
                  <p className="text-sm text-slate-400 mb-4">
                    NIST-selected post-quantum KEM. Used for key exchange.
                  </p>
                  <Button onClick={() => generateQuantumKey("kyber")} className="w-full">
                    <Key className="w-4 h-4 mr-2" />
                    Generate KYBER-768 Keypair
                  </Button>
                </div>
                <div className="p-4 bg-slate-800/50 rounded border border-slate-700">
                  <h3 className="font-medium text-white mb-2">DILITHIUM (Digital Signatures)</h3>
                  <p className="text-sm text-slate-400 mb-4">
                    NIST-selected post-quantum signature scheme.
                  </p>
                  <Button onClick={() => generateQuantumKey("dilithium")} className="w-full">
                    <Shield className="w-4 h-4 mr-2" />
                    Generate DILITHIUM-3 Keypair
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Quantum Security Status</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-3 bg-slate-800/50 rounded">
                  <span className="text-slate-400">Mode</span>
                  <Badge variant="outline">{dashboard?.quantum?.mode}</Badge>
                </div>
                <div className="flex items-center justify-between p-3 bg-slate-800/50 rounded">
                  <span className="text-slate-400">Hash Algorithm</span>
                  <span className="text-white font-mono">{dashboard?.quantum?.algorithms?.hash}</span>
                </div>
                <div className="p-3 bg-slate-800/50 rounded">
                  <span className="text-slate-400 block mb-2">Supported KEM Algorithms</span>
                  <div className="flex gap-2">
                    {dashboard?.quantum?.algorithms?.kem?.map((alg) => (
                      <Badge key={alg} variant="secondary">{alg}</Badge>
                    ))}
                  </div>
                </div>
                <div className="p-3 bg-slate-800/50 rounded">
                  <span className="text-slate-400 block mb-2">Supported Signature Algorithms</span>
                  <div className="flex gap-2">
                    {dashboard?.quantum?.algorithms?.signatures?.map((alg) => (
                      <Badge key={alg} variant="secondary">{alg}</Badge>
                    ))}
                  </div>
                </div>
                <div className="p-3 bg-yellow-900/20 border border-yellow-700/50 rounded text-sm text-yellow-300">
                  {dashboard?.quantum?.note}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* AI Tab */}
        <TabsContent value="ai" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Ollama Configuration */}
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Settings className="w-5 h-5" />
                  Ollama Configuration
                </CardTitle>
                <CardDescription>Configure local LLM for enhanced reasoning</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <label className="text-sm text-slate-400 block mb-1">Ollama URL</label>
                    <Input
                      value={ollamaConfig.base_url}
                      onChange={(e) => setOllamaConfig({ ...ollamaConfig, base_url: e.target.value })}
                      placeholder="http://host.docker.internal:11434"
                      className="bg-slate-800 border-slate-700"
                      data-testid="ollama-url-input"
                    />
                    <p className="text-xs text-slate-500 mt-1">
                      Use <code>http://host.docker.internal:11434</code> when Ollama runs on the host.
                    </p>
                  </div>
                  <div>
                    <label className="text-sm text-slate-400 block mb-1">Model</label>
                    <Input
                      value={ollamaConfig.model}
                      onChange={(e) => setOllamaConfig({ ...ollamaConfig, model: e.target.value })}
                      placeholder="mistral"
                      className="bg-slate-800 border-slate-700"
                    />
                  </div>
                  <Button onClick={configureOllama} className="w-full">
                    <Zap className="w-4 h-4 mr-2" />
                    Connect to Ollama
                  </Button>
                  <div className="p-3 bg-slate-800/50 rounded">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Status</span>
                      <Badge variant={dashboard?.ai?.ollama?.status === "connected" ? "success" : "secondary"}>
                        {dashboard?.ai?.ollama?.status}
                      </Badge>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* AI Query */}
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <MessageSquare className="w-5 h-5" />
                  Security Query
                </CardTitle>
                <CardDescription>Ask about MITRE techniques, threats, and responses</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <Input
                    value={aiQuery}
                    onChange={(e) => setAiQuery(e.target.value)}
                    onKeyPress={(e) => e.key === "Enter" && queryAI()}
                    placeholder="e.g., Tell me about MITRE technique T1003"
                    className="bg-slate-800 border-slate-700"
                    data-testid="ai-query-input"
                  />
                  <Button onClick={queryAI} className="w-full">
                    <Brain className="w-4 h-4 mr-2" />
                    Query AI
                  </Button>
                  {aiResponse && (
                    <div className="p-3 bg-slate-800/50 rounded border border-slate-700">
                      <p className="text-white mb-2">{aiResponse.conclusion}</p>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline">Confidence: {(aiResponse.confidence * 100).toFixed(0)}%</Badge>
                        <span className="text-xs text-slate-500">{aiResponse.model_used}</span>
                      </div>
                      {aiResponse.recommendations?.length > 0 && (
                        <div className="mt-2">
                          <span className="text-xs text-slate-400">Recommendations:</span>
                          <ul className="list-disc list-inside text-sm text-slate-300 mt-1">
                            {aiResponse.recommendations.map((rec, i) => (
                              <li key={i}>{rec}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Threat Analysis */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                Threat Analysis
              </CardTitle>
              <CardDescription>Analyze threats with AI reasoning</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                <Input
                  value={analyzeData.title}
                  onChange={(e) => setAnalyzeData({ ...analyzeData, title: e.target.value })}
                  placeholder="Threat title (e.g., Mimikatz Detected)"
                  className="bg-slate-800 border-slate-700"
                  data-testid="analyze-title-input"
                />
                <Input
                  value={analyzeData.description}
                  onChange={(e) => setAnalyzeData({ ...analyzeData, description: e.target.value })}
                  placeholder="Description"
                  className="bg-slate-800 border-slate-700"
                />
                <Input
                  value={analyzeData.command_line}
                  onChange={(e) => setAnalyzeData({ ...analyzeData, command_line: e.target.value })}
                  placeholder="Command line (optional)"
                  className="bg-slate-800 border-slate-700"
                />
              </div>
              <Button onClick={analyzeThreat} className="mb-4">
                <Eye className="w-4 h-4 mr-2" />
                Analyze Threat
              </Button>
              {aiAnalysis && (
                <div className="p-4 bg-slate-800/50 rounded border border-slate-700">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-medium text-white">{aiAnalysis.threat_type?.replace(/_/g, " ")}</h3>
                    <div className="flex gap-2">
                      <Badge variant={aiAnalysis.severity === "critical" ? "destructive" : "secondary"}>
                        {aiAnalysis.severity}
                      </Badge>
                      <Badge variant="outline">Risk: {aiAnalysis.risk_score}/100</Badge>
                    </div>
                  </div>
                  <p className="text-slate-300 mb-4">{aiAnalysis.description}</p>
                  <div className="grid grid-cols-2 gap-4 mb-4">
                    <div>
                      <span className="text-sm text-slate-400">MITRE Techniques</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {aiAnalysis.mitre_techniques?.map((t) => (
                          <Badge key={t} variant="secondary" className="text-xs">{t}</Badge>
                        ))}
                      </div>
                    </div>
                    <div>
                      <span className="text-sm text-slate-400">Playbook</span>
                      <p className="text-white font-mono text-sm mt-1">{aiAnalysis.playbook_id || "None"}</p>
                    </div>
                  </div>
                  <div>
                    <span className="text-sm text-slate-400">Recommended Actions</span>
                    <ul className="list-disc list-inside text-sm text-slate-300 mt-1">
                      {aiAnalysis.recommended_actions?.slice(0, 5).map((action, i) => (
                        <li key={i}>{action}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
