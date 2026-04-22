import { useEffect, useMemo, useState } from 'react';
import apiClient from '../lib/api';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { Terminal, RefreshCw, Server, Database, ShieldCheck, AlertTriangle, Play } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Textarea } from '../components/ui/textarea';
import { toast } from 'sonner';

const OsqueryFleetPage = () => {
  const { token } = useAuth();
  const [status, setStatus] = useState(null);
  const [stats, setStats] = useState(null);
  const [hosts, setHosts] = useState([]);
  const [queries, setQueries] = useState([]);
  const [results, setResults] = useState([]);
  const [queryText, setQueryText] = useState('SELECT pid, name, cmdline FROM processes LIMIT 25;');
  const [querySearch, setQuerySearch] = useState('');
  const [liveResult, setLiveResult] = useState(null);
  const [running, setRunning] = useState(false);

  const headers = useMemo(() => ({ Authorization: `Bearer ${token}` }), [token]);

  const loadOverview = async () => {
    try {
      const [statusRes, statsRes, hostsRes, queriesRes, resultsRes] = await Promise.all([
        apiClient.get(`/osquery/status`),
        apiClient.get(`/osquery/stats`),
        apiClient.get(`/osquery/hosts?limit=25`),
        apiClient.get(`/osquery/queries?limit=30`),
        apiClient.get(`/osquery/results?limit=30`),
      ]);

      setStatus(statusRes.data);
      setStats(statsRes.data);
      setHosts(hostsRes.data.hosts || []);
      setQueries(queriesRes.data.queries || []);
      setResults(resultsRes.data.records || []);
    } catch (err) {
      toast.error('Failed to load osquery/Fleet data');
    }
  };

  useEffect(() => {
    if (token) {
      loadOverview();
    }
  }, [token]);

  const searchQueries = async () => {
    try {
      const res = await apiClient.get(`/osquery/queries?limit=50&query=${encodeURIComponent(querySearch)}`, { headers });
      setQueries(res.data.queries || []);
      if (res.data.fleet_error) {
        toast.info(`Fleet: ${res.data.fleet_error}`);
      }
    } catch (err) {
      toast.error('Failed to search osquery queries');
    }
  };

  const runLiveQuery = async () => {
    setRunning(true);
    try {
      const res = await apiClient.post(
        `/osquery/live-query`,
        { sql: queryText, selected: {} }
      );
      setLiveResult(res.data);
      if (res.data.ok) {
        toast.success('Fleet live query dispatched');
      } else {
        toast.warning(res.data.message || 'Fleet live query failed');
      }
    } catch (err) {
      toast.error('Failed to execute live query');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-6" data-testid="osquery-fleet-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Terminal className="w-6 h-6 text-emerald-400" />
            osquery / Fleet Integration
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Endpoint telemetry ingestion and Fleet live query orchestration
          </p>
        </div>
        <Button
          onClick={loadOverview}
          variant="outline"
          className="border-emerald-500/50 text-emerald-400 hover:bg-emerald-500/10"
        >
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Fleet Configured</p>
          <p className="text-xl font-bold text-white mt-1">{status?.fleet?.configured ? 'Yes' : 'No'}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Fleet Reachable</p>
          <p className="text-xl font-bold text-white mt-1">{status?.fleet?.reachable ? 'Yes' : 'No'}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.16 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Result Events</p>
          <p className="text-xl font-bold text-white mt-1">{stats?.result_events || 0}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.24 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Unique Hosts</p>
          <p className="text-xl font-bold text-white mt-1">{stats?.unique_hosts || 0}</p>
        </motion.div>
      </div>

      {status?.fleet?.error && (
        <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" />
          Fleet connection issue: {status.fleet.error}
        </div>
      )}

      {status?.environment && (
        <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-700 text-slate-300 text-sm">
          <p className="font-medium text-white mb-2">osquery/Fleet environment</p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
            <p>FLEET_BASE_URL: {status.environment.FLEET_BASE_URL_set ? 'set' : 'missing'}</p>
            <p>FLEET_API_TOKEN: {status.environment.FLEET_API_TOKEN_set ? 'set' : 'missing'}</p>
            <p>OSQUERY_RESULTS_LOG: {status.environment.OSQUERY_RESULTS_LOG || 'unset'}</p>
            <p>OSQUERY_DEMO_MODE: {String(status.environment.OSQUERY_DEMO_MODE)}</p>
          </div>
        </div>
      )}

      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Play className="w-5 h-5 text-emerald-400" />
            Fleet Live Query
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <Textarea
            value={queryText}
            onChange={(e) => setQueryText(e.target.value)}
            className="bg-slate-800 border-slate-700 text-white min-h-[130px] font-mono text-xs"
          />
          <Button onClick={runLiveQuery} disabled={running} className="bg-emerald-600 hover:bg-emerald-700 text-white">
            {running ? 'Running...' : 'Run Query'}
          </Button>
          {liveResult && (
            <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700">
              <p className="text-white text-sm font-medium">{liveResult.ok ? 'Dispatched' : 'Failed'}</p>
              <p className="text-slate-400 text-xs mt-1">{liveResult.message}</p>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            Query Catalog
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-3">
            <Input
              value={querySearch}
              onChange={(e) => setQuerySearch(e.target.value)}
              placeholder="Search queries or ATT&CK technique (e.g. T1547)"
              className="bg-slate-800 border-slate-700 text-white"
            />
            <Button onClick={searchQueries} variant="outline" className="border-emerald-500/40 text-emerald-300">Search</Button>
          </div>
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {queries.map((q, idx) => (
              <div key={`${q.name}-${idx}`} className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-white font-medium">{q.name}</p>
                  <Badge variant="outline" className="text-slate-300 border-slate-500/30">{q.source || 'builtin'}</Badge>
                </div>
                <p className="text-slate-400 text-xs mt-1">{q.description}</p>
                <p className="text-emerald-300 text-xs mt-2 font-mono truncate">{q.sql}</p>
                <div className="flex flex-wrap gap-2 mt-2">
                  {(q.attack_techniques || []).map((t) => (
                    <Badge key={t} variant="outline" className="text-cyan-300 border-cyan-500/30">{t}</Badge>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Server className="w-5 h-5 text-emerald-400" />
              Fleet Hosts
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 max-h-72 overflow-y-auto">
              {hosts.map((h, idx) => (
                <div key={`${h.id || h.hostname || idx}`} className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                  <p className="text-white text-sm font-medium">{h.hostname || 'unknown-host'}</p>
                  <p className="text-slate-400 text-xs mt-1">{h.platform || 'unknown'} {h.os_version ? `• ${h.os_version}` : ''}</p>
                  <p className="text-slate-500 text-xs mt-1">Last seen: {h.last_seen || 'n/a'}</p>
                </div>
              ))}
              {hosts.length === 0 && <p className="text-slate-500 text-sm">No Fleet hosts returned.</p>}
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Database className="w-5 h-5 text-emerald-400" />
              osquery Result Events
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 max-h-72 overflow-y-auto">
              {results.map((r, idx) => (
                <div key={idx} className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                  <p className="text-white text-sm font-medium">{r.name || r.query_name || 'unnamed_query'}</p>
                  <p className="text-slate-400 text-xs mt-1">Host: {r.hostIdentifier || r.host_identifier || 'unknown'}</p>
                  <p className="text-slate-500 text-xs mt-1">Action: {r.action || 'snapshot'}</p>
                </div>
              ))}
              {results.length === 0 && <p className="text-slate-500 text-sm">No osquery result records found.</p>}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default OsqueryFleetPage;
