import { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { FlaskConical, RefreshCw, Play, CheckCircle, AlertTriangle, Clock } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const AtomicValidationPage = () => {
  const { token } = useAuth();
  const headers = useMemo(() => ({ Authorization: `Bearer ${token}` }), [token]);

  const [status, setStatus] = useState(null);
  const [jobs, setJobs] = useState([]);
  const [runs, setRuns] = useState([]);
  const [summary, setSummary] = useState(null);
  const [runningJob, setRunningJob] = useState(null);

  const loadData = async () => {
    try {
      const [statusRes, jobsRes, runsRes] = await Promise.all([
        axios.get(`${API}/atomic-validation/status`, { headers }),
        axios.get(`${API}/atomic-validation/jobs`, { headers }),
        axios.get(`${API}/atomic-validation/runs?limit=30`, { headers }),
      ]);
      setStatus(statusRes.data);
      setJobs(jobsRes.data.jobs || []);
      setRuns(runsRes.data.runs || []);
      setSummary(runsRes.data.summary || null);
    } catch (err) {
      toast.error('Failed to load Atomic validation data');
    }
  };

  useEffect(() => {
    if (token) {
      loadData();
    }
  }, [token]);

  const runJob = async (jobId, dryRun = false) => {
    setRunningJob(jobId + (dryRun ? '-dry' : ''));
    try {
      const res = await axios.post(
        `${API}/atomic-validation/run`,
        { job_id: jobId, dry_run: dryRun },
        { headers }
      );
      if (res.data.status === 'success' || res.data.status === 'dry_run') {
        toast.success(`Atomic job ${jobId} ${dryRun ? 'dry-run' : 'completed'}`);
      } else {
        toast.warning(`Atomic job ${jobId} failed: ${res.data.message || 'unknown error'}`);
      }
      await loadData();
    } catch (err) {
      toast.error('Failed to run Atomic validation job');
    } finally {
      setRunningJob(null);
    }
  };

  return (
    <div className="space-y-6" data-testid="atomic-validation-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <FlaskConical className="w-6 h-6 text-rose-400" />
            Atomic Red Team Validation Jobs
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Weekly ATT&CK emulation jobs for detection quality scoring (target score &gt;= 4)
          </p>
        </div>
        <Button
          onClick={loadData}
          variant="outline"
          className="border-rose-500/50 text-rose-400 hover:bg-rose-500/10"
        >
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Atomic Enabled</p>
          <p className="text-xl font-bold text-white">{status?.enabled ? 'Yes' : 'No'}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Runner Available</p>
          <p className="text-xl font-bold text-white">{status?.runner_available ? 'Yes' : 'No'}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.16 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Jobs Configured</p>
          <p className="text-xl font-bold text-white">{status?.jobs_configured || 0}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.24 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Validated Techniques</p>
          <p className="text-xl font-bold text-white">{summary?.validated_technique_count || 0}</p>
        </motion.div>
      </div>

      {!status?.atomic_root_exists && (
        <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" />
          Atomic Red Team path not found inside backend container: {status?.atomic_root || 'n/a'}
        </div>
      )}

      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Play className="w-5 h-5 text-rose-400" />
            Weekly Validation Jobs
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {jobs.map((job) => (
            <div key={job.job_id} className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <p className="text-white font-medium">{job.name}</p>
                  <p className="text-slate-400 text-xs mt-1">{job.description}</p>
                  <div className="flex flex-wrap gap-2 mt-2">
                    {(job.techniques || []).map((t) => (
                      <Badge key={t} variant="outline" className="text-cyan-300 border-cyan-500/30">{t}</Badge>
                    ))}
                    <Badge variant="outline" className="text-amber-300 border-amber-500/30">{job.frequency}</Badge>
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => runJob(job.job_id, true)}
                    disabled={runningJob !== null}
                    className="border-slate-600 text-slate-300"
                  >
                    Dry Run
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => runJob(job.job_id, false)}
                    disabled={runningJob !== null}
                    className="bg-rose-600 hover:bg-rose-700 text-white"
                  >
                    {runningJob === job.job_id ? 'Running...' : 'Run'}
                  </Button>
                </div>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Clock className="w-5 h-5 text-rose-400" />
            Recent Validation Runs
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {runs.map((run) => (
              <div key={run.run_id} className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-white font-medium">{run.job_name}</p>
                  <Badge
                    variant="outline"
                    className={
                      run.status === 'success'
                        ? 'text-green-400 border-green-500/30'
                        : run.status === 'dry_run'
                        ? 'text-blue-400 border-blue-500/30'
                        : 'text-red-400 border-red-500/30'
                    }
                  >
                    {run.status}
                  </Badge>
                </div>
                <p className="text-slate-400 text-xs mt-1">{run.message}</p>
                <div className="flex flex-wrap gap-2 mt-2">
                  {(run.techniques || []).map((t) => (
                    <Badge key={t} variant="outline" className="text-cyan-300 border-cyan-500/30">{t}</Badge>
                  ))}
                </div>
                <div className="text-slate-500 text-xs mt-2 flex items-center gap-2">
                  <CheckCircle className="w-3 h-3" />
                  Started: {run.started_at ? new Date(run.started_at).toLocaleString() : 'n/a'}
                </div>
              </div>
            ))}
            {runs.length === 0 && (
              <div className="p-4 bg-slate-800/40 border border-slate-700 rounded-lg text-slate-500 text-sm">
                No validation jobs have run yet.
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default AtomicValidationPage;
