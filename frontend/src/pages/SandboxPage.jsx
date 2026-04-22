import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { 
  Box, 
  Activity, 
  Play, 
  FileText, 
  Link2,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Clock,
  XCircle,
  Upload,
  Search,
  Shield,
  Cpu
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API_URL = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

const SandboxPage = () => {
  const { token } = useAuth();
  const [stats, setStats] = useState(null);
  const [analyses, setAnalyses] = useState([]);
  const [queue, setQueue] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('analyses');
  const [selectedAnalysis, setSelectedAnalysis] = useState(null);
  const [urlInput, setUrlInput] = useState('');

  const demoSandboxData = {
    stats: {
      total_analyses: 14,
      queue_length: 1,
      running: 1,
      vm_pool_size: 3,
      signatures_available: 128,
      by_verdict: {
        malicious: 6,
        suspicious: 3,
        clean: 4,
        unknown: 1,
      },
      by_sample_type: {
        pe: 7,
        url: 4,
        pdf: 2,
        script: 1,
      },
    },
    analyses: [
      {
        analysis_id: 'demo_sbx_001',
        sample_name: 'invoice_viewer.exe',
        sample_hash: '4f7f8b4e32d41d8a0a1d6f9d9be501fc2f5f2e86d3b8a41cf8a4f6aa9f1010aa',
        status: 'completed',
        verdict: 'malicious',
        score: 92,
        sample_type: 'pe',
      },
      {
        analysis_id: 'demo_sbx_002',
        sample_name: 'hxxp://secure-update-check.example',
        sample_hash: 'url',
        status: 'running',
        verdict: 'unknown',
        score: 0,
        sample_type: 'url',
      },
    ],
    queue: {
      queue_length: 1,
      running: 1,
      max_concurrent: 2,
      vm_pool: ['vm-win10-a', 'vm-win11-b', 'vm-ubuntu-c'],
      queued_ids: ['demo_sbx_003'],
    },
    analysisDetails: {
      demo_sbx_001: {
        analysis_id: 'demo_sbx_001',
        sample_name: 'invoice_viewer.exe',
        sample_hash: '4f7f8b4e32d41d8a0a1d6f9d9be501fc2f5f2e86d3b8a41cf8a4f6aa9f1010aa',
        sample_type: 'pe',
        status: 'completed',
        verdict: 'malicious',
        score: 92,
        vm_name: 'vm-win10-a',
        duration_seconds: 143,
        signatures_matched: [
          {
            name: 'Credential Harvester',
            severity: 'critical',
            description: 'Observed browser credential scraping and staged exfiltration behavior.',
          },
          {
            name: 'Persistence via Run Key',
            severity: 'high',
            description: 'Sample attempted to create a HKCU Run key for relaunch on login.',
          },
        ],
        process_activity: [
          {
            process_name: 'invoice_viewer.exe',
            pid: 3148,
            command_line: 'C:\\Users\\analyst\\Downloads\\invoice_viewer.exe --silent',
            is_suspicious: true,
            suspicion_reason: 'Spawned hidden PowerShell child process',
          },
          {
            process_name: 'powershell.exe',
            pid: 3221,
            command_line: 'powershell -nop -w hidden -enc ...',
            is_suspicious: true,
            suspicion_reason: 'Encoded command execution',
          },
        ],
        network_activity: [
          { dest_ip: '185.193.88.12', dest_port: 443, protocol: 'tcp', data_size: 18422 },
          { dest_ip: '45.67.221.9', dest_port: 8080, protocol: 'tcp', data_size: 9120 },
        ],
      },
      demo_sbx_002: {
        analysis_id: 'demo_sbx_002',
        sample_name: 'hxxp://secure-update-check.example',
        sample_hash: 'url',
        sample_type: 'url',
        status: 'running',
        verdict: 'unknown',
        score: 0,
        vm_name: 'vm-ubuntu-c',
        duration_seconds: 38,
        signatures_matched: [],
        process_activity: [
          {
            process_name: 'chromium',
            pid: 4412,
            command_line: '/usr/bin/chromium --headless secure-update-check.example',
            is_suspicious: false,
          },
        ],
        network_activity: [
          { dest_ip: '104.21.32.55', dest_port: 443, protocol: 'tcp', data_size: 2048 },
        ],
      },
    },
  };

  useEffect(() => {
    fetchData();
  }, [token]);

  const fetchData = async () => {
    try {
      const [statsRes, analysesRes, queueRes] = await Promise.all([
        fetch(`${API_URL}/api/sandbox/stats`, {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch(`${API_URL}/api/sandbox/analyses?limit=20`, {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch(`${API_URL}/api/sandbox/queue`, {
          headers: { 'Authorization': `Bearer ${token}` }
        })
      ]);

      if (statsRes.ok) setStats(await statsRes.json());
      if (analysesRes.ok) {
        const data = await analysesRes.json();
        setAnalyses(data.analyses || []);
      }
      if (queueRes.ok) setQueue(await queueRes.json());
    } catch (error) {
      console.error('Failed to fetch sandbox data:', error);
    } finally {
      setLoading(false);
    }
  };

  const submitURL = async () => {
    if (!urlInput.trim()) {
      toast.error('Please enter a URL');
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/sandbox/submit/url`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: urlInput })
      });

      if (response.ok) {
        const result = await response.json();
        toast.success(`URL submitted for analysis: ${result.analysis_id}`);
        setUrlInput('');
        fetchData();
      }
    } catch (error) {
      toast.error('Failed to submit URL');
    }
  };

  const fetchAnalysisDetails = async (analysisId) => {
    try {
      const response = await fetch(`${API_URL}/api/sandbox/analyses/${analysisId}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        const data = await response.json();
        setSelectedAnalysis(data);
      }
    } catch (error) {
      console.error('Failed to fetch analysis details:', error);
    }
  };

  const getStatusIcon = (status) => {
    const icons = {
      completed: <CheckCircle className="w-4 h-4 text-green-400" />,
      running: <Activity className="w-4 h-4 text-blue-400 animate-pulse" />,
      pending: <Clock className="w-4 h-4 text-yellow-400" />,
      failed: <XCircle className="w-4 h-4 text-red-400" />,
      timeout: <XCircle className="w-4 h-4 text-orange-400" />
    };
    return icons[status] || <Clock className="w-4 h-4 text-slate-400" />;
  };

  const getVerdictColor = (verdict) => {
    const colors = {
      malicious: 'text-red-400 bg-red-400/10',
      suspicious: 'text-orange-400 bg-orange-400/10',
      clean: 'text-green-400 bg-green-400/10',
      unknown: 'text-slate-400 bg-slate-400/10'
    };
    return colors[verdict] || colors.unknown;
  };

  const hasSandboxData = Boolean(
    stats?.total_analyses ||
    stats?.running ||
    analyses.length ||
    queue?.queue_length
  );

  const effectiveStats = hasSandboxData ? stats : demoSandboxData.stats;
  const effectiveAnalyses = hasSandboxData ? analyses : demoSandboxData.analyses;
  const effectiveQueue = hasSandboxData ? queue : demoSandboxData.queue;
  const effectiveSelectedAnalysis = selectedAnalysis || (!hasSandboxData ? demoSandboxData.analysisDetails[effectiveAnalyses[0]?.analysis_id] : null);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-blue-500 font-mono animate-pulse">Loading Sandbox...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 p-6" data-testid="sandbox-page">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-lg bg-orange-500/20 flex items-center justify-center">
              <Box className="w-6 h-6 text-orange-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">Sandbox Analysis</h1>
              <p className="text-slate-400">Dynamic malware analysis in isolated environment</p>
            </div>
          </div>
          <Button onClick={fetchData} variant="outline" className="border-slate-700">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-8">
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-xs">Total Analyses</p>
                <p className="text-xl font-bold text-white">{effectiveStats?.total_analyses || 0}</p>
              </div>
              <FileText className="w-5 h-5 text-blue-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-xs">Queue</p>
                <p className="text-xl font-bold text-white">{effectiveStats?.queue_length || 0}</p>
              </div>
              <Clock className="w-5 h-5 text-yellow-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-xs">Running</p>
                <p className="text-xl font-bold text-white">{effectiveStats?.running || 0}</p>
              </div>
              <Activity className="w-5 h-5 text-green-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-xs">VM Pool</p>
                <p className="text-xl font-bold text-white">{effectiveStats?.vm_pool_size || 0}</p>
              </div>
              <Cpu className="w-5 h-5 text-purple-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-xs">Signatures</p>
                <p className="text-xl font-bold text-white">{effectiveStats?.signatures_available || 0}</p>
              </div>
              <Shield className="w-5 h-5 text-red-400" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Submit Section */}
      <Card className="bg-slate-900/50 border-slate-800 mb-6">
        <CardContent className="p-4">
          <div className="flex gap-4">
            <div className="flex-1">
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="Enter URL to analyze (e.g., http://suspicious-site.com)"
                  className="flex-1 bg-slate-800 border border-slate-700 rounded px-4 py-2 text-white"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  data-testid="sandbox-url-input"
                />
                <Button onClick={submitURL} className="bg-orange-600 hover:bg-orange-700">
                  <Link2 className="w-4 h-4 mr-2" />
                  Analyze URL
                </Button>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Tabs */}
      <div className="flex gap-2 mb-6">
        {['analyses', 'details', 'verdicts'].map((tab) => (
          <Button
            key={tab}
            variant={activeTab === tab ? 'default' : 'ghost'}
            onClick={() => setActiveTab(tab)}
            className={activeTab === tab ? 'bg-orange-600 hover:bg-orange-700' : 'text-slate-400'}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </Button>
        ))}
      </div>

      {activeTab === 'analyses' && (
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <FileText className="w-5 h-5 text-orange-400" />
              Recent Analyses
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {effectiveAnalyses.length === 0 ? (
                <p className="text-slate-500 text-center py-8">No analyses yet. Submit a file or URL to begin.</p>
              ) : (
                effectiveAnalyses.map((analysis) => (
                  <div
                    key={analysis.analysis_id}
                    className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg cursor-pointer hover:bg-slate-800"
                    onClick={() => {
                      if (hasSandboxData) {
                        fetchAnalysisDetails(analysis.analysis_id);
                      } else {
                        setSelectedAnalysis(demoSandboxData.analysisDetails[analysis.analysis_id] || null);
                      }
                      setActiveTab('details');
                    }}
                  >
                    <div className="flex items-center gap-4">
                      {getStatusIcon(analysis.status)}
                      <div>
                        <p className="text-white font-medium">{analysis.sample_name}</p>
                        <p className="text-slate-500 text-xs">{analysis.sample_hash}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getVerdictColor(analysis.verdict)}`}>
                        {analysis.verdict}
                      </span>
                      <span className="text-slate-400 text-sm">Score: {analysis.score}</span>
                      <span className="text-slate-500 text-xs capitalize">{analysis.sample_type}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {activeTab === 'details' && effectiveSelectedAnalysis && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Analysis Overview */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">Analysis Overview</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="flex justify-between">
                  <span className="text-slate-400">Sample</span>
                  <span className="text-white">{effectiveSelectedAnalysis.sample_name}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Hash</span>
                  <span className="text-white font-mono text-xs">{effectiveSelectedAnalysis.sample_hash?.slice(0, 32)}...</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Type</span>
                  <span className="text-white capitalize">{effectiveSelectedAnalysis.sample_type}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Status</span>
                  <span className="text-white capitalize">{effectiveSelectedAnalysis.status}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Verdict</span>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getVerdictColor(effectiveSelectedAnalysis.verdict)}`}>
                    {effectiveSelectedAnalysis.verdict}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Score</span>
                  <span className="text-white font-bold text-lg">{effectiveSelectedAnalysis.score}/100</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">VM</span>
                  <span className="text-white">{effectiveSelectedAnalysis.vm_name}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Duration</span>
                  <span className="text-white">{effectiveSelectedAnalysis.duration_seconds}s</span>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Signatures Matched */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                Signatures Matched ({effectiveSelectedAnalysis.signatures_matched?.length || 0})
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 max-h-64 overflow-auto">
                {(effectiveSelectedAnalysis.signatures_matched || []).map((sig, idx) => (
                  <div key={idx} className="p-3 bg-slate-800/50 rounded-lg">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-white font-medium">{sig.name}</span>
                      <span className={`px-2 py-0.5 rounded text-xs ${
                        sig.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                        sig.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                        'bg-yellow-500/20 text-yellow-400'
                      }`}>
                        {sig.severity}
                      </span>
                    </div>
                    <p className="text-slate-400 text-xs">{sig.description}</p>
                  </div>
                ))}
                {(!effectiveSelectedAnalysis.signatures_matched || effectiveSelectedAnalysis.signatures_matched.length === 0) && (
                  <p className="text-slate-500 text-center py-4">No signatures matched</p>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Process Activity */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Cpu className="w-5 h-5 text-blue-400" />
                Process Activity
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 max-h-64 overflow-auto">
                {(effectiveSelectedAnalysis.process_activity || []).map((proc, idx) => (
                  <div key={idx} className="p-3 bg-slate-800/50 rounded-lg">
                    <div className="flex items-center justify-between">
                      <span className="text-white font-mono text-sm">{proc.process_name}</span>
                      <span className="text-slate-400 text-xs">PID: {proc.pid}</span>
                    </div>
                    <p className="text-slate-500 text-xs truncate">{proc.command_line}</p>
                    {proc.is_suspicious && (
                      <span className="text-red-400 text-xs">{proc.suspicion_reason}</span>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Network Activity */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Activity className="w-5 h-5 text-green-400" />
                Network Activity
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 max-h-64 overflow-auto">
                {(effectiveSelectedAnalysis.network_activity || []).map((net, idx) => (
                  <div key={idx} className="p-3 bg-slate-800/50 rounded-lg">
                    <div className="flex items-center justify-between">
                      <span className="text-white font-mono text-sm">{net.dest_ip}:{net.dest_port}</span>
                      <span className="text-slate-400 text-xs">{net.protocol}</span>
                    </div>
                    <p className="text-slate-500 text-xs">{net.data_size} bytes</p>
                  </div>
                ))}
                {(!effectiveSelectedAnalysis.network_activity || effectiveSelectedAnalysis.network_activity.length === 0) && (
                  <p className="text-slate-500 text-center py-4">No network activity detected</p>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {activeTab === 'verdicts' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">By Verdict</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4">
                {Object.entries(effectiveStats?.by_verdict || {}).map(([verdict, count]) => (
                  <div key={verdict} className={`p-4 rounded-lg ${getVerdictColor(verdict)}`}>
                    <p className="text-2xl font-bold">{count}</p>
                    <p className="text-sm capitalize">{verdict}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="text-white">By Sample Type</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {Object.entries(effectiveStats?.by_sample_type || {}).map(([type, count]) => (
                  <div key={type} className="flex items-center justify-between">
                    <span className="text-slate-300 capitalize">{type}</span>
                    <span className="text-white font-mono">{count}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
};

export default SandboxPage;
