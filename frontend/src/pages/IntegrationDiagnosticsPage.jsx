import { useCallback, useEffect, useMemo, useState } from 'react';
import apiClient from '../lib/api';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';

const parseJsonOrNull = (value) => {
  const trimmed = String(value || '').trim();
  if (!trimmed) return {};
  try {
    return JSON.parse(trimmed);
  } catch {
    return null;
  }
};

const statusBadge = (status) => {
  const s = String(status || '').toLowerCase();
  if (s === 'completed' || s === 'success') return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
  if (s === 'running') return 'bg-cyan-500/20 text-cyan-200 border-cyan-500/40';
  if (s === 'failed' || s === 'error') return 'bg-red-500/20 text-red-300 border-red-500/40';
  return 'bg-slate-700/40 text-slate-200 border-slate-600/40';
};

export default function IntegrationDiagnosticsPage() {
  const [tools, setTools] = useState([]);
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [lastRun, setLastRun] = useState(null);

  const [tool, setTool] = useState('zeek');
  const [runtimeTarget, setRuntimeTarget] = useState('server');
  const [agentId, setAgentId] = useState('');
  const [paramsJson, setParamsJson] = useState('{}');

  const sortedTools = useMemo(() => [...tools].sort(), [tools]);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [toolsRes, jobsRes] = await Promise.all([
        apiClient.get('/integrations/runtime/tools'),
        apiClient.get('/integrations/jobs'),
      ]);
      setTools(toolsRes.data?.tools || []);
      setJobs(jobsRes.data?.jobs || jobsRes.data?.executions || []);
    } catch (e) {
      toast.error('Failed to load integration catalog');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const runTool = async () => {
    const params = parseJsonOrNull(paramsJson);
    if (params == null) {
      toast.error('Params must be valid JSON');
      return;
    }
    setRunning(true);
    try {
      const payload = {
        tool,
        params,
        runtime_target: runtimeTarget,
        agent_id: agentId || null,
      };
      const res = await apiClient.post('/integrations/runtime/run', payload);
      setLastRun(res.data || null);
      toast.success(`Launched ${tool} (${res.data?.job_id || 'job'})`);
      await refresh();
    } catch (e) {
      toast.error(e?.response?.data?.detail || 'Failed to launch tool');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h2 className="text-xl font-semibold text-white">Integration Diagnostics</h2>
        <p className="text-sm text-slate-400">
          Run the same integration tools the local agent uses (containers or scripts), and inspect their job status.
        </p>
      </div>

      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white">Launch Tool</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div>
              <div className="text-xs text-slate-400 mb-1">Tool</div>
              <select
                className="w-full rounded-md bg-slate-950/40 border border-slate-800 px-3 py-2 text-sm text-slate-200"
                value={tool}
                onChange={(e) => setTool(e.target.value)}
                disabled={loading}
              >
                {sortedTools.length ? (
                  sortedTools.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))
                ) : (
                  <option value="zeek">zeek</option>
                )}
              </select>
            </div>

            <div>
              <div className="text-xs text-slate-400 mb-1">Runtime</div>
              <select
                className="w-full rounded-md bg-slate-950/40 border border-slate-800 px-3 py-2 text-sm text-slate-200"
                value={runtimeTarget}
                onChange={(e) => setRuntimeTarget(e.target.value)}
              >
                <option value="server">server</option>
                <option value="agent">agent</option>
              </select>
            </div>

            <div>
              <div className="text-xs text-slate-400 mb-1">Agent ID (optional)</div>
              <input
                className="w-full rounded-md bg-slate-950/40 border border-slate-800 px-3 py-2 text-sm text-slate-200"
                value={agentId}
                onChange={(e) => setAgentId(e.target.value)}
                placeholder="unified-agent-id"
              />
            </div>

            <div className="flex items-end gap-2">
              <Button onClick={runTool} disabled={running || loading}>
                Run
              </Button>
              <Button variant="outline" className="border-slate-700" onClick={refresh} disabled={loading}>
                Refresh
              </Button>
            </div>
          </div>

          <div>
            <div className="text-xs text-slate-400 mb-1">Params (JSON)</div>
            <textarea
              className="w-full min-h-28 rounded-md bg-slate-950/40 border border-slate-800 px-3 py-2 text-xs text-slate-200 font-mono"
              value={paramsJson}
              onChange={(e) => setParamsJson(e.target.value)}
            />
          </div>
        </CardContent>
      </Card>

      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-white">Latest Response</CardTitle>
          <Badge variant="outline" className="border-slate-700 text-slate-300">
            {lastRun ? 'loaded' : 'empty'}
          </Badge>
        </CardHeader>
        <CardContent>
          {lastRun ? (
            <pre className="whitespace-pre-wrap rounded-md border border-slate-800 bg-slate-950/40 p-3 text-xs text-slate-200 font-mono overflow-auto max-h-80">
              {JSON.stringify(lastRun, null, 2)}
            </pre>
          ) : (
            <div className="text-sm text-slate-400">Run a tool to see the raw JSON response here.</div>
          )}
        </CardContent>
      </Card>

      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-white">Recent Jobs</CardTitle>
          <Badge variant="outline" className="border-slate-700 text-slate-300">
            {jobs.length}
          </Badge>
        </CardHeader>
        <CardContent className="space-y-2">
          {jobs.length === 0 ? (
            <div className="text-sm text-slate-400">No jobs yet. Run a tool to create one.</div>
          ) : (
            <div className="space-y-2">
              {jobs.slice(0, 20).map((job) => (
                <div
                  key={job.id || job.job_id || JSON.stringify(job).slice(0, 32)}
                  className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-slate-800 bg-slate-950/20 px-3 py-2"
                >
                  <div className="flex items-center gap-2">
                    <Badge className={statusBadge(job.status)} variant="outline">
                      {job.status || 'unknown'}
                    </Badge>
                    <span className="text-sm text-slate-200">{job.tool || job.name || 'tool'}</span>
                    <span className="text-xs text-slate-500">{job.id || job.job_id}</span>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-slate-400">
                    <span>target: {job.params?.runtime_target || job.runtime_target || 'server'}</span>
                    {job.result?.agent_id || job.agent_id ? (
                      <span>agent: {job.result?.agent_id || job.agent_id}</span>
                    ) : null}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
