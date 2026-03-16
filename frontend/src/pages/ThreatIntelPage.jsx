import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import JobCard from './JobCard';
import { 
  Database, Search, RefreshCw, Shield, 
  Globe, Hash, Link as LinkIcon, CheckCircle, XCircle,
  TrendingUp, Clock, Activity, Server, Laptop, Network
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Input } from '../components/ui/input';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const ThreatIntelPage = () => {
  const { token } = useAuth();
  const [stats, setStats] = useState(null);
  const [searchValue, setSearchValue] = useState('');
  const [searchResult, setSearchResult] = useState(null);
  const [recentMatches, setRecentMatches] = useState([]);
  const [loading, setLoading] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [runtimeTarget, setRuntimeTarget] = useState('server');
  const [selectedAgentId, setSelectedAgentId] = useState('');
  const [agents, setAgents] = useState([]);
  const [supportedTools, setSupportedTools] = useState([]);
  const [toolInputFile, setToolInputFile] = useState('');
  const [toolParamsJson, setToolParamsJson] = useState('{}');

  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    fetchStats();
    fetchRecentMatches();
    fetchJobs();
    fetchAgents();
    fetchSupportedTools();
    const iv = setInterval(() => fetchJobs(), 5000);
    return () => clearInterval(iv);
  }, [token]);

  const [amassDomain, setAmassDomain] = useState('');
  const [jobs, setJobs] = useState([]);
  const [jobStarting, setJobStarting] = useState(false);

  const fetchJobs = async () => {
    try {
      const res = await axios.get(`${API}/integrations/jobs`, { headers });
      setJobs(res.data || []);
    } catch (err) {
      console.error('Failed to fetch integration jobs', err);
    }
  };

  const fetchAgents = async () => {
    try {
      const res = await axios.get(`${API}/unified/agents`, { headers });
      const rows = (res.data?.agents || []).filter((a) => a?.agent_id);
      setAgents(rows);
      if (!selectedAgentId && rows.length) {
        const preferred = rows.find((a) => a.status === 'online') || rows[0];
        setSelectedAgentId(preferred.agent_id);
      }
    } catch (err) {
      console.error('Failed to fetch unified agents', err);
    }
  };

  const fetchSupportedTools = async () => {
    try {
      const res = await axios.get(`${API}/integrations/runtime/tools`, { headers });
      setSupportedTools(res.data?.tools || []);
    } catch (err) {
      console.error('Failed to fetch runtime tools', err);
    }
  };

  const fetchArtifacts = async (jobId) => {
    try {
      const res = await axios.get(`${API}/integrations/artifacts/${jobId}`, { headers });
      return res.data || { artifacts: [] };
    } catch (err) {
      console.error('Failed to fetch artifacts', err);
      return { artifacts: [] };
    }
  };

  const handleStartAmass = async () => {
    if (!amassDomain.trim()) return toast.error('Provide a domain');
    await launchIntegration('amass', { domain: amassDomain.trim() });
    setAmassDomain('');
  };

  const handleUploadHostLogs = async (file) => {
    if (!file) return toast.error('Select a log file');
    setLoading(true);
    try {
      const text = await file.text();
      const res = await axios.post(`${API}/integrations/ingest/host`, { source: 'sysmon-upload', raw: text }, { headers });
      toast.success(`Host ingest: ${res.data.result?.ingested || 0} indicators`);
      fetchJobs();
    } catch (err) {
      console.error(err);
      toast.error('Host ingest failed');
    } finally {
      setLoading(false);
    }
  };

  const handleStartVelociraptor = async () => {
    await launchIntegration('velociraptor', { collection_name: '' });
  };

  const handleStartPurpleSharp = async () => {
    await launchIntegration('purplesharp', { target: '' });
  };

  const launchIntegration = async (tool, params = {}) => {
    if (runtimeTarget !== 'server' && !selectedAgentId) {
      toast.error('Select a unified agent for agent runtime target');
      return;
    }
    setJobStarting(true);
    try {
      let parsedParams = {};
      if (toolParamsJson && toolParamsJson.trim()) {
        try {
          parsedParams = JSON.parse(toolParamsJson);
        } catch (e) {
          toast.error('Custom params JSON is invalid');
          setJobStarting(false);
          return;
        }
      }
      const payload = {
        tool,
        params: { ...(parsedParams || {}), ...(params || {}) },
        runtime_target: runtimeTarget,
        agent_id: runtimeTarget === 'server' ? null : selectedAgentId,
      };
      const res = await axios.post(`${API}/integrations/runtime/run`, payload, { headers });
      const queueId = res.data?.queue_id;
      const decisionId = res.data?.decision_id;
      if (queueId || decisionId) {
        toast.success(`${tool} queued for approval • queue ${queueId || 'n/a'}`);
      } else {
        toast.success(`${tool} launched • job ${res.data?.job_id || 'created'}`);
      }
      fetchJobs();
    } catch (err) {
      console.error(err);
      toast.error(`Failed to launch ${tool}`);
    } finally {
      setJobStarting(false);
    }
  };

  const fetchStats = async () => {
    try {
      const res = await axios.get(`${API}/threat-intel/stats`, { headers });
      setStats(res.data);
    } catch (err) {
      toast.error('Failed to fetch threat intel stats');
    }
  };

  const fetchRecentMatches = async () => {
    try {
      const res = await axios.get(`${API}/threat-intel/matches/recent?limit=20`, { headers });
      setRecentMatches(res.data);
    } catch (err) {
      console.error('Failed to fetch recent matches');
    }
  };

  const handleSearch = async () => {
    if (!searchValue.trim()) return;
    setLoading(true);
    try {
      const res = await axios.post(`${API}/threat-intel/check`, 
        { value: searchValue.trim() }, 
        { headers }
      );
      setSearchResult(res.data);
      if (res.data.matched) {
        toast.warning('Threat indicator matched!');
      } else {
        toast.success('No threats found');
      }
    } catch (err) {
      toast.error('Search failed');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateFeeds = async () => {
    setUpdating(true);
    try {
      const res = await axios.post(`${API}/threat-intel/update`, {}, { headers });
      toast.success(`Feeds updated: ${res.data.stats?.total_indicators || 0} indicators`);
      fetchStats();
    } catch (err) {
      toast.error('Failed to update feeds');
    } finally {
      setUpdating(false);
    }
  };

  const handleIngestFile = async (file) => {
    if (!file) return;
    setLoading(true);
    try {
      const text = await file.text();
      // Expecting either an array of indicators or an object with 'hosts' or similar
      let payload;
      try {
        payload = JSON.parse(text);
      } catch (e) {
        toast.error('Invalid JSON file');
        setLoading(false);
        return;
      }

      // Normalize to indicators list
      let indicators = [];
      if (Array.isArray(payload)) {
        indicators = payload.map(v => (typeof v === 'string' ? { value: v } : v));
      } else if (payload.hosts) {
        indicators = payload.hosts.map(h => ({ type: 'domain', value: h }));
      } else if (payload.indicators) {
        indicators = payload.indicators;
      } else {
        // Attempt to extract common keys
        indicators = Object.keys(payload).map(k => ({ type: 'domain', value: k }));
      }

      const res = await axios.post(`${API}/threat-intel/ingest`, { source: 'amass-upload', indicators }, { headers });
      toast.success(`Ingested: ${res.data.result.ingested || 0} indicators`);
      fetchStats();
    } catch (err) {
      console.error(err);
      toast.error('Ingest failed');
    } finally {
      setLoading(false);
    }
  };

  const getTypeIcon = (type) => {
    switch(type) {
      case 'ip': return <Globe className="w-4 h-4" />;
      case 'domain': return <Globe className="w-4 h-4" />;
      case 'url': return <LinkIcon className="w-4 h-4" />;
      case 'md5': case 'sha1': case 'sha256': return <Hash className="w-4 h-4" />;
      default: return <Database className="w-4 h-4" />;
    }
  };

  return (
    <div className="space-y-6" data-testid="threat-intel-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Database className="w-6 h-6 text-blue-400" />
            Threat Intelligence
          </h1>
          <p className="text-slate-400 text-sm mt-1">Real-time IOC lookup against threat feeds</p>
        </div>
        <div className="flex items-center gap-2">
          <input
            id="osint-upload"
            type="file"
            accept="application/json"
            style={{ display: 'none' }}
            onChange={(e) => e.target.files[0] && handleIngestFile(e.target.files[0])}
          />
          <label htmlFor="osint-upload">
            <Button variant="ghost" className="text-slate-300/80" data-testid="ingest-btn">
              Upload OSINT
            </Button>
          </label>
          <Button 
            onClick={handleUpdateFeeds} 
            disabled={updating}
            variant="outline"
            className="border-blue-500/50 text-blue-400 hover:bg-blue-500/10"
            data-testid="update-feeds-btn"
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${updating ? 'animate-spin' : ''}`} />
            {updating ? 'Updating...' : 'Update Feeds'}
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} 
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
              <Database className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Total Indicators</p>
              <p className="text-2xl font-bold text-white">{stats?.total_indicators?.toLocaleString() || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
              <Activity className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">Active Feeds</p>
              <p className="text-2xl font-bold text-white">{stats?.enabled_feeds?.length || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-amber-500/10 flex items-center justify-center">
              <Globe className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">IP Indicators</p>
              <p className="text-2xl font-bold text-white">{stats?.by_type?.ip?.toLocaleString() || 0}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
          className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center">
              <LinkIcon className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <p className="text-slate-400 text-sm">URL Indicators</p>
              <p className="text-2xl font-bold text-white">{stats?.by_type?.url?.toLocaleString() || 0}</p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* IOC Search */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Search className="w-5 h-5 text-blue-400" />
            IOC Lookup
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <Input
              placeholder="Enter IP, domain, URL, or file hash..."
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              className="bg-slate-800 border-slate-700 text-white"
              data-testid="ioc-search-input"
            />
            <Button onClick={handleSearch} disabled={loading} data-testid="ioc-search-btn">
              {loading ? 'Searching...' : 'Search'}
            </Button>
          </div>

          {searchResult && (
            <motion.div 
              initial={{ opacity: 0, y: 10 }} 
              animate={{ opacity: 1, y: 0 }}
              className={`mt-4 p-4 rounded-lg border ${searchResult.matched ? 'bg-red-500/10 border-red-500/30' : 'bg-green-500/10 border-green-500/30'}`}
            >
              <div className="flex items-center gap-2 mb-2">
                {searchResult.matched ? (
                  <XCircle className="w-5 h-5 text-red-400" />
                ) : (
                  <CheckCircle className="w-5 h-5 text-green-400" />
                )}
                <span className={`font-semibold ${searchResult.matched ? 'text-red-400' : 'text-green-400'}`}>
                  {searchResult.matched ? 'THREAT DETECTED' : 'No Threat Found'}
                </span>
              </div>
              <p className="text-slate-400 text-sm">
                Type: {searchResult.query_type} | Value: {searchResult.query_value}
              </p>
              {searchResult.indicator && (
                <div className="mt-2 p-2 bg-slate-800/50 rounded">
                  <p className="text-white text-sm">Source: {searchResult.indicator.source}</p>
                  <p className="text-slate-400 text-sm">Level: {searchResult.indicator.threat_level}</p>
                  <p className="text-slate-400 text-sm">Confidence: {searchResult.indicator.confidence}%</p>
                </div>
              )}
            </motion.div>
          )}
        </CardContent>
      </Card>

      {/* Feed Status */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-green-400" />
            Feed Status
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {stats?.by_feed && Object.entries(stats.by_feed).map(([name, data]) => (
              <div key={name} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-white font-medium capitalize">{name.replace(/_/g, ' ')}</p>
                    <p className="text-slate-400 text-sm">{data.total?.toLocaleString() || 0} indicators</p>
                  </div>
                  <Badge variant="outline" className="text-green-400 border-green-500/30">Active</Badge>
                </div>
                {data.last_updated && (
                  <p className="text-slate-500 text-xs mt-2 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    Last updated: {new Date(data.last_updated).toLocaleString()}
                  </p>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Integrations */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-blue-400" />
            Integrations
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-4">
            <div className="flex flex-col gap-1">
              <span className="text-xs text-slate-400">Runtime target</span>
              <select
                value={runtimeTarget}
                onChange={(e) => setRuntimeTarget(e.target.value)}
                className="bg-slate-800 border border-slate-700 text-white rounded-md px-3 py-2"
              >
                <option value="server">Server runtime</option>
                <option value="unified_agent_local">Unified agent (local)</option>
                <option value="unified_agent_remote">Unified agent (remote)</option>
              </select>
            </div>
            <div className="flex flex-col gap-1">
              <span className="text-xs text-slate-400">Target unified agent</span>
              <select
                value={selectedAgentId}
                onChange={(e) => setSelectedAgentId(e.target.value)}
                disabled={runtimeTarget === 'server'}
                className="bg-slate-800 border border-slate-700 text-white rounded-md px-3 py-2 disabled:opacity-60"
              >
                <option value="">Auto-select</option>
                {agents.map((agent) => (
                  <option key={agent.agent_id} value={agent.agent_id}>
                    {agent.agent_id} ({agent.status || 'unknown'})
                  </option>
                ))}
              </select>
            </div>
            <div className="flex flex-col gap-1">
              <span className="text-xs text-slate-400">Optional source file path</span>
              <Input
                placeholder="/data/export.json"
                value={toolInputFile}
                onChange={(e) => setToolInputFile(e.target.value)}
                className="bg-slate-800 border-slate-700 text-white"
              />
            </div>
            <div className="flex flex-col gap-1">
              <span className="text-xs text-slate-400">Optional custom params JSON</span>
              <textarea
                value={toolParamsJson}
                onChange={(e) => setToolParamsJson(e.target.value)}
                className="bg-slate-800 border border-slate-700 text-white rounded-md px-3 py-2 min-h-[42px]"
                placeholder='{"action":"status"}'
              />
            </div>
          </div>

          <div className="flex gap-2 items-center mb-4">
            <Input placeholder="example.com" value={amassDomain} onChange={(e)=>setAmassDomain(e.target.value)} className="bg-slate-800 border-slate-700 text-white" />
            <Button onClick={handleStartAmass} disabled={jobStarting} data-testid="run-amass-btn">
              {jobStarting ? 'Starting...' : 'Run Amass'}
            </Button>
            <Button onClick={handleStartVelociraptor} disabled={jobStarting} data-testid="run-velociraptor-btn">
              {jobStarting ? 'Starting...' : 'Run Velociraptor'}
            </Button>
            <Button onClick={handleStartPurpleSharp} disabled={jobStarting} data-testid="run-purplesharp-btn">
              {jobStarting ? 'Starting...' : 'Run PurpleSharp'}
            </Button>
            <Button onClick={() => launchIntegration('arkime', toolInputFile ? { input_file: toolInputFile } : { action: 'status' })} disabled={jobStarting}>
              Run Arkime
            </Button>
            <Button onClick={() => launchIntegration('bloodhound', toolInputFile ? { input_file: toolInputFile } : { action: 'status' })} disabled={jobStarting}>
              Run BloodHound
            </Button>
            <Button onClick={() => launchIntegration('spiderfoot', toolInputFile ? { input_file: toolInputFile } : { action: 'status' })} disabled={jobStarting}>
              Run SpiderFoot
            </Button>
            <Button onClick={() => launchIntegration('sigma', { action: 'reload' })} disabled={jobStarting}>
              Run Sigma
            </Button>
            <Button onClick={() => launchIntegration('atomic', { action: 'status' })} disabled={jobStarting}>
              Run Atomic
            </Button>
            <Button onClick={() => launchIntegration('trivy', { action: 'status' })} disabled={jobStarting}>
              Run Trivy
            </Button>
            <Button onClick={() => launchIntegration('falco', { action: 'status' })} disabled={jobStarting}>
              Run Falco
            </Button>
            <Button onClick={() => launchIntegration('suricata', { action: 'status' })} disabled={jobStarting}>
              Run Suricata
            </Button>
            <Button onClick={() => launchIntegration('yara', { action: 'status' })} disabled={jobStarting}>
              Run YARA
            </Button>
            <Button onClick={() => launchIntegration('cuckoo', { action: 'status' })} disabled={jobStarting}>
              Run Cuckoo
            </Button>
            <Button onClick={() => launchIntegration('osquery', { action: 'status' })} disabled={jobStarting}>
              Run Osquery
            </Button>
            <Button onClick={() => launchIntegration('zeek', { action: 'status' })} disabled={jobStarting}>
              Run Zeek
            </Button>
            <Button onClick={fetchJobs} variant="outline">Refresh Jobs</Button>
          </div>

          <div className="mb-4 flex items-center gap-2 text-xs text-slate-400">
            {runtimeTarget === 'server' ? <Server className="w-4 h-4" /> : <Laptop className="w-4 h-4" />}
            <span>
              Launch mode: <span className="text-slate-200">{runtimeTarget}</span>
              {runtimeTarget !== 'server' && selectedAgentId ? ` • agent ${selectedAgentId}` : ''}
            </span>
            <Network className="w-4 h-4" />
            <span>{supportedTools.length ? `${supportedTools.length} supported tools` : 'Loading tools...'}</span>
          </div>

          <div className="flex items-center gap-2 mb-4">
            <input id="host-log-upload" type="file" accept="text/*,application/json" style={{ display: 'none' }} onChange={(e) => e.target.files[0] && handleUploadHostLogs(e.target.files[0])} />
            <label htmlFor="host-log-upload"><Button variant="ghost">Upload Host Logs</Button></label>
          </div>

          <div className="space-y-2">
            {jobs.slice(0,10).map(j => (
              <JobCard key={j.id} job={j} fetchArtifacts={fetchArtifacts} headers={headers} API={API} />
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default ThreatIntelPage;
