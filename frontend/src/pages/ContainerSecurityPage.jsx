import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Container, Search, Shield, AlertTriangle, 
  CheckCircle, XCircle, Activity, Box, RefreshCw, Eye, Radar, Wifi
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { toast } from 'sonner';
import SeraphPageHeader from '../components/SeraphPageHeader';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const INTEGRATION_RUNTIME_DEFAULT_ACTIONS = {
  trivy: 'scan_all',
  falco: 'alerts',
  suricata: 'alerts',
};

const CONTAINER_ACCENTS = {
  gold: { border: 'rgba(251,191,36,0.36)', glow: 'rgba(251,191,36,0.12)' },
  magenta: { border: 'rgba(255,43,214,0.42)', glow: 'rgba(255,43,214,0.16)' },
  green: { border: 'rgba(57,255,20,0.34)', glow: 'rgba(57,255,20,0.12)' },
  violet: { border: 'rgba(188,19,254,0.38)', glow: 'rgba(188,19,254,0.14)' },
};

const containerPanelStyle = (accent) => ({
  background: 'linear-gradient(160deg, rgba(8,18,34,0.92), rgba(3,9,18,0.96))',
  border: `1px solid ${accent.border}`,
  boxShadow: `0 0 14px ${accent.glow}, inset 0 0 8px rgba(255,255,255,0.02)`,
  borderRadius: '14px',
});

const INTEGRATION_RUNTIME_TOOLS = Object.keys(INTEGRATION_RUNTIME_DEFAULT_ACTIONS);

const ContainerSecurityPage = () => {
  const { token } = useAuth();
  const [stats, setStats] = useState(null);
  const [containers, setContainers] = useState([]);
  const [scanResults, setScanResults] = useState([]);
  const [imageName, setImageName] = useState('');
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(false);
  const [runtimeStatus, setRuntimeStatus] = useState(null);
  const [integrationStatus, setIntegrationStatus] = useState({});
  const [integrationBusy, setIntegrationBusy] = useState(false);

  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    fetchStats();
    fetchContainers();
    fetchScanHistory();
    fetchRuntimeStatus();
    fetchIntegrationStatus();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  const fetchStats = async () => {
    try {
      const res = await axios.get(`${API}/containers/stats`, { headers });
      setStats(res.data);
    } catch (err) {
      toast.error('Failed to fetch container stats');
    }
  };

  const fetchContainers = async () => {
    try {
      const res = await axios.get(`${API}/containers`, { headers });
      setContainers(res.data.containers || []);
    } catch (err) {
      console.error('Failed to fetch containers');
    }
  };

  const fetchScanHistory = async () => {
    try {
      const res = await axios.get(`${API}/containers/scans/history`, { headers });
      setScanResults(res.data.scans || []);
    } catch (err) {
      console.error('Failed to fetch scan history');
    }
  };

  const fetchRuntimeStatus = async () => {
    try {
      const res = await axios.get(`${API}/containers/runtime-status`, { headers });
      setRuntimeStatus(res.data);
    } catch (err) {
      console.error('Failed to fetch runtime status');
    }
  };

  const fetchIntegrationStatus = async () => {
    setIntegrationBusy(true);
    try {
      const requests = INTEGRATION_RUNTIME_TOOLS.map(async (tool) => {
        const res = await axios.post(
          `${API}/integrations/runtime/run`,
          {
            tool,
            runtime_target: 'server',
            params: { action: 'status' },
          },
          { headers },
        );
        return [tool, res.data || {}];
      });

      const entries = await Promise.allSettled(requests);
      const next = {};
      for (const row of entries) {
        if (row.status === 'fulfilled') {
          const [tool, payload] = row.value;
          next[tool] = payload;
        }
      }
      setIntegrationStatus(next);
    } catch (err) {
      toast.error('Failed to refresh integration runtime status');
    } finally {
      setIntegrationBusy(false);
    }
  };

  const handleRunIntegration = async (tool) => {
    const action = INTEGRATION_RUNTIME_DEFAULT_ACTIONS[tool] || 'status';
    const params = { action };

    setIntegrationBusy(true);
    try {
      await axios.post(
        `${API}/integrations/runtime/run`,
        {
          tool,
          runtime_target: 'server',
          params,
        },
        { headers },
      );
      toast.success(`Launched ${tool} (${action})`);
      await fetchIntegrationStatus();
      await fetchContainers();
    } catch (err) {
      toast.error(err?.response?.data?.detail || `Failed to launch ${tool}`);
    } finally {
      setIntegrationBusy(false);
    }
  };

  const handleScanImage = async () => {
    if (!imageName.trim()) return;
    setScanning(true);
    try {
      const res = await axios.post(`${API}/containers/scan`, 
        { image_name: imageName.trim() }, 
        { headers }
      );
      if (res.data.total_vulnerabilities > 0) {
        toast.warning(`Found ${res.data.total_vulnerabilities} vulnerabilities`);
      } else {
        toast.success('No vulnerabilities found');
      }
      fetchScanHistory();
    } catch (err) {
      toast.error('Scan failed');
    } finally {
      setScanning(false);
    }
  };

  const handleScanAll = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${API}/containers/scan-all`, {}, { headers });
      toast.success(`Scanned ${res.data.images_scanned} images`);
      fetchScanHistory();
    } catch (err) {
      toast.error('Failed to scan all images');
    } finally {
      setLoading(false);
    }
  };

  const handleCheckContainer = async (containerId) => {
    try {
      const res = await axios.get(`${API}/containers/${containerId}/security`, { headers });
      if (res.data.issues?.length > 0) {
        toast.warning(`Found ${res.data.issues.length} security issues`);
      } else {
        toast.success('Container is secure');
      }
    } catch (err) {
      toast.error('Security check failed');
    }
  };

  const getSeverityColor = (severity) => {
    switch(severity?.toLowerCase()) {
      case 'critical': return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'high': return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'medium': return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'low': return 'text-green-400 bg-green-500/10 border-green-500/30';
      default: return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    }
  };

  return (
    <div className="space-y-6" data-testid="container-security-page">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <SeraphPageHeader
          eyebrow="seraph · containers · runtime defense"
          title="Container Security"
          tagline="> Trivy vulnerability scanning and runtime monitoring"
          accent="gold"
          status="MONITORED"
        />
        <Button className="sophia-btn sophia-btn-refresh" onClick={handleScanAll} disabled={loading} variant="outline" style={{ borderColor: 'rgba(251,191,36,0.5)', color: '#fde68a' }}>
          <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
          Scan All Images
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          className="p-4" style={containerPanelStyle(CONTAINER_ACCENTS.green)}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center">
              {stats?.trivy_enabled ? 
                <CheckCircle className="w-5 h-5 text-green-400" /> : 
                <XCircle className="w-5 h-5 text-red-400" />
              }
            </div>
            <div>
              <p className="sophia-terminal-label text-sm">Trivy Scanner</p>
              <p className={`sophia-terminal-value font-bold ${stats?.trivy_enabled ? 'text-green-400' : 'text-red-400'}`}>
                {stats?.trivy_enabled ? 'Installed' : 'Not Installed'}
              </p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="p-4" style={containerPanelStyle(CONTAINER_ACCENTS.violet)}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ background: 'rgba(188,19,254,0.14)' }}>
              <Box className="w-5 h-5" style={{ color: '#bc13fe' }} />
            </div>
            <div>
              <p className="sophia-terminal-label text-sm">Running Containers</p>
              <p className="sophia-terminal-value text-2xl font-bold text-white">{containers.length}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          className="p-4" style={containerPanelStyle(CONTAINER_ACCENTS.magenta)}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ background: 'rgba(255,43,214,0.14)' }}>
              <Search className="w-5 h-5" style={{ color: '#ff2bd6' }} />
            </div>
            <div>
              <p className="sophia-terminal-label text-sm">Cached Scans</p>
              <p className="sophia-terminal-value text-2xl font-bold text-white">{stats?.cached_scans || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
          className="p-4" style={containerPanelStyle(CONTAINER_ACCENTS.gold)}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-amber-500/10 flex items-center justify-center">
              <Activity className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <p className="sophia-terminal-label text-sm">Runtime Events</p>
              <p className="sophia-terminal-value text-2xl font-bold text-white">{stats?.runtime_events || 0}</p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Runtime Security: Falco + Suricata */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-purple-400" />
            Runtime Security Engines
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Falco */}
            <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Radar className="w-5 h-5 text-rose-400" />
                  <span className="text-white font-medium">Falco</span>
                </div>
                <Badge variant="outline" className={
                  runtimeStatus?.falco?.running
                    ? 'text-green-400 border-green-500/30'
                    : runtimeStatus?.falco?.available === false
                    ? 'text-slate-400 border-slate-500/30'
                    : 'text-red-400 border-red-500/30'
                }>
                  {runtimeStatus?.falco?.running ? 'Running' : runtimeStatus?.falco?.status || 'Unknown'}
                </Badge>
              </div>
              <p className="text-slate-400 text-sm">Runtime threat detection for containers</p>
              <p className="text-slate-500 text-xs mt-2">
                Events captured: {runtimeStatus?.falco?.event_count ?? '—'}
              </p>
              <Button
                size="sm"
                variant="outline"
                className="mt-3 border-rose-500/40 text-rose-400 hover:bg-rose-500/10"
                onClick={fetchRuntimeStatus}
              >
                <RefreshCw className="w-3 h-3 mr-1" />
                Refresh
              </Button>
            </div>

            {/* Suricata */}
            <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Wifi className="w-5 h-5 text-sky-400" />
                  <span className="text-white font-medium">Suricata</span>
                </div>
                <Badge variant="outline" className={
                  runtimeStatus?.suricata?.running
                    ? 'text-green-400 border-green-500/30'
                    : runtimeStatus?.suricata?.available === false
                    ? 'text-slate-400 border-slate-500/30'
                    : 'text-red-400 border-red-500/30'
                }>
                  {runtimeStatus?.suricata?.running ? 'Running' : runtimeStatus?.suricata?.status || 'Unknown'}
                </Badge>
              </div>
              <p className="text-slate-400 text-sm">Network IDS/IPS for container traffic</p>
              <p className="text-slate-500 text-xs mt-2">
                Events captured: {runtimeStatus?.suricata?.event_count ?? '—'}
              </p>
              <Button
                size="sm"
                variant="outline"
                className="mt-3 border-sky-500/40 text-sky-400 hover:bg-sky-500/10"
                onClick={fetchRuntimeStatus}
              >
                <RefreshCw className="w-3 h-3 mr-1" />
                Refresh
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* On-Demand Integration Runtime */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            On-Demand Integrations
          </CardTitle>
          <p className="text-xs text-slate-400">
            Integrations stay idle until you run them. Use Run to start only the tool you need.
          </p>
        </CardHeader>
        <CardContent>
          <div className="flex justify-end mb-3">
            <Button
              size="sm"
              variant="outline"
              className="border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10"
              onClick={fetchIntegrationStatus}
              disabled={integrationBusy}
            >
              <RefreshCw className={`w-3 h-3 mr-1 ${integrationBusy ? 'animate-spin' : ''}`} />
              Refresh Integrations
            </Button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {INTEGRATION_RUNTIME_TOOLS.map((tool) => {
              const row = integrationStatus[tool] || {};
              const state = String(row.status || 'unknown').toLowerCase();
              const ok = state === 'completed' || state === 'success';
              return (
                <div key={tool} className="p-3 rounded-lg border border-slate-700 bg-slate-800/40">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-cyan-300 font-medium">{tool}</span>
                    <Badge
                      variant="outline"
                      className={ok ? 'text-green-400 border-green-500/30' : 'text-slate-300 border-slate-600/40'}
                    >
                      {row.status || 'unknown'}
                    </Badge>
                  </div>
                  <div className="text-[11px] text-slate-400 mb-3">
                    default action: {INTEGRATION_RUNTIME_DEFAULT_ACTIONS[tool]}
                  </div>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-slate-600 text-slate-200"
                      onClick={fetchIntegrationStatus}
                      disabled={integrationBusy}
                    >
                      Status
                    </Button>
                    <Button
                      size="sm"
                      className="bg-indigo-600 hover:bg-indigo-500 text-white"
                      onClick={() => handleRunIntegration(tool)}
                      disabled={integrationBusy}
                    >
                      Run
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Image Scanner */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Search className="w-5 h-5 text-cyan-400" />
            Scan Container Image
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <Input
              placeholder="Enter image name (e.g., nginx:latest)"
              value={imageName}
              onChange={(e) => setImageName(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleScanImage()}
              className="bg-slate-800 border-slate-700 text-white"
            />
            <Button onClick={handleScanImage} disabled={scanning}>
              {scanning ? 'Scanning...' : 'Scan Image'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Running Containers */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Box className="w-5 h-5 text-blue-400" />
            Running Containers
          </CardTitle>
        </CardHeader>
        <CardContent>
          {containers.length > 0 ? (
            <div className="space-y-2">
              {containers.map((container) => (
                <div key={container.container_id} 
                  className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10 rounded bg-slate-700 flex items-center justify-center">
                      <Container className="w-5 h-5 text-cyan-400" />
                    </div>
                    <div>
                      <p className="text-white font-medium">{container.name}</p>
                      <p className="text-slate-400 text-sm">{container.image}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="text-right">
                      <p className="text-sm text-slate-400">Security Score</p>
                      <p className={`font-bold ${container.security_score >= 80 ? 'text-green-400' : container.security_score >= 50 ? 'text-amber-400' : 'text-red-400'}`}>
                        {container.security_score}/100
                      </p>
                    </div>
                    {container.is_privileged && (
                      <Badge variant="destructive">Privileged</Badge>
                    )}
                    <Button size="sm" variant="outline" onClick={() => handleCheckContainer(container.container_id)}>
                      <Eye className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-slate-400">
              <Container className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No running containers detected</p>
              <p className="text-sm">Docker containers will appear here when running</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Scan Results */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-green-400" />
            Recent Scan Results
          </CardTitle>
        </CardHeader>
        <CardContent>
          {scanResults.length > 0 ? (
            <div className="space-y-3">
              {scanResults.slice(0, 10).map((scan) => (
                <div key={scan.scan_id} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-white font-medium">{scan.image_name}</p>
                    <Badge variant="outline" className={scan.scan_status === 'completed' ? 'text-green-400 border-green-500/30' : 'text-red-400 border-red-500/30'}>
                      {scan.scan_status}
                    </Badge>
                  </div>
                  <div className="flex gap-4 text-sm">
                    <span className="text-red-400">Critical: {scan.critical_count || 0}</span>
                    <span className="text-orange-400">High: {scan.high_count || 0}</span>
                    <span className="text-amber-400">Medium: {scan.medium_count || 0}</span>
                    <span className="text-green-400">Low: {scan.low_count || 0}</span>
                  </div>
                  <p className="text-slate-500 text-xs mt-2">
                    Scanned: {new Date(scan.scanned_at).toLocaleString()}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-slate-400">
              <Search className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No scan results yet</p>
              <p className="text-sm">Scan an image to see vulnerability results</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default ContainerSecurityPage;
