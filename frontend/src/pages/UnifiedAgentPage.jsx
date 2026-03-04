import { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { useAuth } from "../context/AuthContext";
import { toast } from "sonner";
import {
  Cpu,
  Shield,
  Activity,
  Wifi,
  Bluetooth,
  Network,
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCw,
  Download,
  Terminal,
  Database,
  Server,
  Radio,
  Eye,
  Zap
} from "lucide-react";

const rawBackendUrl = process.env.REACT_APP_BACKEND_URL?.trim();
const API_URL = rawBackendUrl || "";
const API_ROOT = API_URL ? `${API_URL}/api` : '/api';

export default function UnifiedAgentPage() {
  const { token } = useAuth();
  const [agents, setAgents] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedAgent, setSelectedAgent] = useState(null);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [token]);

  const fetchData = async () => {
    try {
      const headers = { Authorization: `Bearer ${token}` };
      
      const [agentsRes, statsRes] = await Promise.all([
        fetch(`${API_ROOT}/unified/agents`, { headers }),
        fetch(`${API_ROOT}/unified/stats`, { headers })
      ]);
      
      if (agentsRes.ok) {
        const agentsData = await agentsRes.json();
        setAgents(agentsData.agents || []);
      }
      
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }
    } catch (error) {
      console.error("Failed to fetch agent data:", error);
    } finally {
      setLoading(false);
    }
  };

  const sendCommand = async (agentId, command, params = {}) => {
    try {
      const response = await fetch(`${API_ROOT}/unified/agents/${agentId}/command`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          command_type: command,
          parameters: params,
          priority: "normal"
        })
      });
      
      if (response.ok) {
        toast.success(`Command "${command}" sent to agent`);
      } else {
        toast.error("Failed to send command");
      }
    } catch (error) {
      toast.error("Error sending command");
    }
  };

  const runBulkCommand = async (command, params = {}, successLabel = 'Command') => {
    const onlineAgents = agents.filter((agent) => (agent.status || '').toLowerCase() === 'online');
    if (onlineAgents.length === 0) {
      toast.warning('No online agents available for bulk command');
      return;
    }

    const results = await Promise.allSettled(
      onlineAgents.map((agent) => sendCommand(agent.agent_id, command, params))
    );

    const succeeded = results.filter((r) => r.status === 'fulfilled').length;
    toast.success(`${successLabel} sent to ${succeeded}/${onlineAgents.length} online agents`);
    fetchData();
  };

  const getStatusColor = (status) => {
    switch (status) {
      case "online": return "text-green-400 bg-green-500/20 border-green-500/30";
      case "offline": return "text-red-400 bg-red-500/20 border-red-500/30";
      case "warning": return "text-yellow-400 bg-yellow-500/20 border-yellow-500/30";
      default: return "text-slate-400 bg-slate-500/20 border-slate-500/30";
    }
  };

  const getPlatformIcon = (platform) => {
    switch (platform?.toLowerCase()) {
      case "windows": return "🪟";
      case "linux": return "🐧";
      case "darwin":
      case "macos": return "🍎";
      case "android": return "🤖";
      default: return "💻";
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-cyan-400 animate-pulse">Loading Unified Agents...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Cpu className="w-6 h-6 text-cyan-500" />
            Unified Agent Dashboard
          </h1>
          <p className="text-slate-400">Metatron/Seraph cross-platform security agents</p>
        </div>
        <div className="flex gap-2">
          <Button onClick={fetchData} variant="outline" size="sm">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Button className="bg-cyan-600 hover:bg-cyan-700" onClick={() => window.open(`${API_ROOT}/unified/agent/download`, '_blank')}>
            <Download className="w-4 h-4 mr-2" />
            Download Agent
          </Button>
        </div>
      </div>

      {/* Stats Overview */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Total Agents</p>
                  <p className="text-2xl font-bold text-white">{stats.total_agents || 0}</p>
                </div>
                <Cpu className="w-8 h-8 text-cyan-500" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900/50 border-slate-800">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Online</p>
                  <p className="text-2xl font-bold text-green-400">{stats.online_agents || 0}</p>
                </div>
                <CheckCircle className="w-8 h-8 text-green-500" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900/50 border-slate-800">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Threats Detected</p>
                  <p className="text-2xl font-bold text-red-400">{stats.total_threats || 0}</p>
                </div>
                <AlertTriangle className="w-8 h-8 text-red-500" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900/50 border-slate-800">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Auto-Kills</p>
                  <p className="text-2xl font-bold text-orange-400">{stats.auto_kills || 0}</p>
                </div>
                <Zap className="w-8 h-8 text-orange-500" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900/50 border-slate-800">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Blocked</p>
                  <p className="text-2xl font-bold text-purple-400">{stats.blocked_threats || 0}</p>
                </div>
                <Shield className="w-8 h-8 text-purple-500" />
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Agent Features Info */}
      <Card className="bg-gradient-to-r from-cyan-500/10 to-purple-500/10 border-cyan-500/30">
        <CardContent className="p-6">
          <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" />
            Unified Agent v2.0 Features
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="flex items-center gap-2 text-sm">
              <Activity className="w-4 h-4 text-green-400" />
              <span className="text-slate-300">Process Monitoring</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Network className="w-4 h-4 text-blue-400" />
              <span className="text-slate-300">Network Scanning</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Wifi className="w-4 h-4 text-purple-400" />
              <span className="text-slate-300">WiFi Analysis</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Bluetooth className="w-4 h-4 text-cyan-400" />
              <span className="text-slate-300">Bluetooth Scan</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Zap className="w-4 h-4 text-orange-400" />
              <span className="text-slate-300">Aggressive Auto-Kill</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Database className="w-4 h-4 text-yellow-400" />
              <span className="text-slate-300">SIEM Integration</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Server className="w-4 h-4 text-pink-400" />
              <span className="text-slate-300">VNS Sync</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <Eye className="w-4 h-4 text-red-400" />
              <span className="text-slate-300">AI Analysis</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Agents List */}
      <Tabs defaultValue="agents" className="space-y-4">
        <TabsList className="bg-slate-900/50 border border-slate-800">
          <TabsTrigger value="agents">Active Agents</TabsTrigger>
          <TabsTrigger value="commands">Command Center</TabsTrigger>
          <TabsTrigger value="install">Installation</TabsTrigger>
        </TabsList>

        <TabsContent value="agents">
          <div className="space-y-4">
            {agents.length === 0 ? (
              <Card className="bg-slate-900/50 border-slate-800">
                <CardContent className="py-12 text-center">
                  <Cpu className="w-12 h-12 text-slate-600 mx-auto mb-4" />
                  <h3 className="text-white font-medium mb-2">No Agents Registered</h3>
                  <p className="text-slate-400 text-sm mb-4">
                    Deploy the unified agent to your endpoints to start monitoring
                  </p>
                  <Button className="bg-cyan-600 hover:bg-cyan-700" onClick={() => window.open(`${API_ROOT}/unified/agent/download`, '_blank')}>
                    <Download className="w-4 h-4 mr-2" />
                    Download Agent
                  </Button>
                </CardContent>
              </Card>
            ) : (
              <div className="grid grid-cols-1 gap-4">
                {agents.map((agent) => (
                  <Card key={agent.agent_id} className="bg-slate-900/50 border-slate-800 hover:border-cyan-500/30 transition-colors">
                    <CardContent className="p-6">
                      <div className="flex items-start justify-between">
                        <div className="flex items-start gap-4">
                          <div className="w-12 h-12 rounded-lg bg-slate-800 flex items-center justify-center text-2xl">
                            {getPlatformIcon(agent.platform)}
                          </div>
                          <div>
                            <h3 className="text-white font-medium flex items-center gap-2">
                              {agent.hostname || agent.agent_id}
                              <Badge className={getStatusColor(agent.status)}>
                                {agent.status || "unknown"}
                              </Badge>
                            </h3>
                            <p className="text-slate-400 text-sm">{agent.ip_address || "IP Unknown"}</p>
                            <p className="text-slate-500 text-xs mt-1">ID: {agent.agent_id}</p>
                          </div>
                        </div>
                        <div className="text-right">
                          <p className="text-slate-400 text-sm">v{agent.version || "2.0.0"}</p>
                          <p className="text-slate-500 text-xs">{agent.platform}</p>
                        </div>
                      </div>

                      {/* Telemetry */}
                      <div className="mt-4 pt-4 border-t border-slate-800">
                        <div className="grid grid-cols-4 gap-4 text-sm">
                          <div>
                            <p className="text-slate-500">CPU</p>
                            <p className="text-white font-mono">{agent.cpu_usage?.toFixed(1) || 0}%</p>
                          </div>
                          <div>
                            <p className="text-slate-500">Memory</p>
                            <p className="text-white font-mono">{agent.memory_usage?.toFixed(1) || 0}%</p>
                          </div>
                          <div>
                            <p className="text-slate-500">Threats</p>
                            <p className="text-red-400 font-mono">{agent.threat_count || 0}</p>
                          </div>
                          <div>
                            <p className="text-slate-500">Connections</p>
                            <p className="text-cyan-400 font-mono">{agent.network_connections || 0}</p>
                          </div>
                        </div>
                      </div>

                      {/* Actions */}
                      <div className="mt-4 flex gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => sendCommand(agent.agent_id, "scan")}
                          className="text-cyan-400 border-cyan-500/30"
                        >
                          <Activity className="w-4 h-4 mr-1" />
                          Full Scan
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => sendCommand(agent.agent_id, "update_config")}
                          className="text-green-400 border-green-500/30"
                        >
                          <RefreshCw className="w-4 h-4 mr-1" />
                          Update
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => setSelectedAgent(agent)}
                          className="text-purple-400 border-purple-500/30"
                        >
                          <Eye className="w-4 h-4 mr-1" />
                          Details
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="commands">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Bulk Commands</CardTitle>
              <CardDescription>Send commands to all connected agents</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <Button
                  className="h-24 flex-col bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30"
                  onClick={() => runBulkCommand('scan', {}, 'Full scan')}
                >
                  <Activity className="w-6 h-6 mb-2 text-cyan-400" />
                  <span className="text-cyan-400">Full Scan All</span>
                </Button>
                <Button
                  className="h-24 flex-col bg-green-500/10 hover:bg-green-500/20 border border-green-500/30"
                  onClick={() => runBulkCommand('update_config', {}, 'Update command')}
                >
                  <RefreshCw className="w-6 h-6 mb-2 text-green-400" />
                  <span className="text-green-400">Update All</span>
                </Button>
                <Button
                  className="h-24 flex-col bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/30"
                  onClick={() => runBulkCommand('network_scan', {}, 'Network scan')}
                >
                  <Network className="w-6 h-6 mb-2 text-purple-400" />
                  <span className="text-purple-400">Network Scan</span>
                </Button>
                <Button
                  className="h-24 flex-col bg-orange-500/10 hover:bg-orange-500/20 border border-orange-500/30"
                  onClick={() => runBulkCommand('update_config', { auto_kill: true }, 'Auto-kill enable')}
                >
                  <Zap className="w-6 h-6 mb-2 text-orange-400" />
                  <span className="text-orange-400">Enable Auto-Kill</span>
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="install">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Agent Installation</CardTitle>
              <CardDescription>Deploy the unified agent to your endpoints</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <h4 className="text-cyan-400 font-medium">Quick Install (Python)</h4>
                <pre className="bg-slate-950 p-4 rounded-lg text-sm text-slate-300 font-mono overflow-x-auto">
{`# Download and run the unified agent
curl -sSL ${API_ROOT}/unified/agent/install-script | sudo bash

# Optional explicit server URL
curl -sSL "${API_ROOT}/unified/agent/install-script?server_url=${window.location.origin}" | sudo bash

# Manual package install
curl -sSL ${API_ROOT}/unified/agent/download -o agent.tar.gz
tar -xzf agent.tar.gz
pip install -r requirements.txt
python core/agent.py --server ${window.location.origin}

# Legacy style
python core/agent.py --server ${window.location.origin} --name "My-Endpoint"

# Or install manually
pip install psutil requests
python unified_agent.py --server ${window.location.origin}`}
                </pre>
              </div>

              <div className="space-y-4">
                <h4 className="text-green-400 font-medium">Supported Platforms</h4>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                  {[
                    { name: "Windows", icon: "🪟", status: "Full Support" },
                    { name: "Linux", icon: "🐧", status: "Full Support" },
                    { name: "macOS", icon: "🍎", status: "Full Support" },
                    { name: "Android", icon: "🤖", status: "Termux" },
                    { name: "iOS", icon: "📱", status: "Pythonista" }
                  ].map((platform) => (
                    <div key={platform.name} className="p-4 bg-slate-800/50 rounded-lg text-center">
                      <span className="text-3xl">{platform.icon}</span>
                      <p className="text-white text-sm mt-2">{platform.name}</p>
                      <p className="text-slate-500 text-xs">{platform.status}</p>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
