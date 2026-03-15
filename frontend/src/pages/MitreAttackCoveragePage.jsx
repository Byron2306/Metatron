import { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { Shield, Target, Layers, CheckCircle2, AlertTriangle, RefreshCw } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const scoreLabel = (score) => {
  if (score >= 4) return 'Validated';
  if (score >= 3) return 'High Fidelity';
  if (score === 2) return 'Detection Logic';
  if (score === 1) return 'Telemetry Only';
  return 'Not Covered';
};

const scoreClass = (score) => {
  if (score >= 4) return 'text-green-400 border-green-500/30';
  if (score >= 3) return 'text-cyan-400 border-cyan-500/30';
  if (score === 2) return 'text-amber-400 border-amber-500/30';
  if (score === 1) return 'text-orange-400 border-orange-500/30';
  return 'text-red-400 border-red-500/30';
};

const MitreAttackCoveragePage = () => {
  const { token } = useAuth();
  const headers = useMemo(() => ({ Authorization: `Bearer ${token}` }), [token]);

  const [loading, setLoading] = useState(false);
  const [coverage, setCoverage] = useState(null);

  const loadCoverage = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API}/mitre/coverage`, { headers });
      setCoverage(res.data);
    } catch (err) {
      toast.error('Failed to load MITRE ATT&CK coverage');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (token) {
      loadCoverage();
    }
  }, [token]);

  return (
    <div className="space-y-6" data-testid="mitre-attack-coverage-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-fuchsia-400" />
            MITRE ATT&CK Coverage
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Full-system ATT&CK sweep across implemented detections, telemetry and validation pipelines
          </p>
        </div>
        <Button
          onClick={loadCoverage}
          variant="outline"
          className="border-fuchsia-500/50 text-fuchsia-400 hover:bg-fuchsia-500/10"
          disabled={loading}
        >
          <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Enterprise Techniques</p>
          <p className="text-2xl font-bold text-white">{coverage?.enterprise_total_techniques || 0}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Implemented Techniques</p>
          <p className="text-2xl font-bold text-white">{coverage?.implemented_techniques || 0}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.16 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Implemented Score &gt;= 3</p>
          <p className="text-2xl font-bold text-white">{coverage?.implemented_covered_score_gte3 || 0}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.24 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Implemented Coverage % (&gt;=3)</p>
          <p className="text-2xl font-bold text-white">{coverage?.implemented_coverage_percent_gte3 || 0}%</p>
        </motion.div>
      </div>


      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Observed Techniques (All Sources)</p>
          <p className="text-xl font-semibold text-white">{coverage?.observed_techniques || 0}</p>
        </div>
        <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Enterprise Coverage % (&gt;=3)</p>
          <p className="text-xl font-semibold text-white">{coverage?.coverage_percent_gte3 || 0}%</p>
        </div>
        <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Implemented Tactics</p>
          <p className="text-xl font-semibold text-white">{coverage?.implemented_tactics || 0}</p>
        </div>
      </div>

      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Layers className="w-5 h-5 text-fuchsia-400" />
            ATT&CK Strategy Coverage (Tactics)
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {(coverage?.tactics || []).map((tactic) => (
              <div key={tactic.tactic_id} className="p-3 rounded-lg border border-slate-700 bg-slate-800/40">
                <div className="flex items-center justify-between">
                  <p className="text-white font-medium">{tactic.tactic_name}</p>
                  <Badge variant="outline" className="text-slate-300 border-slate-500/30">{tactic.tactic_id}</Badge>
                </div>
                <p className="text-slate-400 text-xs mt-1">Techniques observed: {tactic.technique_count}</p>
                <p className="text-cyan-400 text-xs">Score &gt;=3: {tactic.score_gte3_count}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Target className="w-5 h-5 text-fuchsia-400" />
              Technique Depth Matrix
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 max-h-[520px] overflow-y-auto pr-1">
              {(coverage?.techniques || []).map((item) => (
                <div key={item.technique} className="p-3 rounded-lg border border-slate-700 bg-slate-800/40">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-white font-medium">{item.technique}</p>
                    <Badge variant="outline" className={scoreClass(item.score)}>
                      S{item.score} {scoreLabel(item.score)}
                    </Badge>
                  </div>
                  <p className="text-slate-400 text-xs mt-1">Tactic: {item.tactic}</p>
                  {item.implemented && (
                    <p className="text-emerald-400 text-xs mt-1">Implemented evidence files: {item.implemented_evidence_count}</p>
                  )}
                  <div className="flex flex-wrap gap-2 mt-2">
                    {(item.sources || []).map((s) => (
                      <Badge key={`${item.technique}-${s}`} variant="outline" className="text-slate-300 border-slate-500/30">
                        {s}
                      </Badge>
                    ))}
                  </div>
                </div>
              ))}
              {(coverage?.techniques || []).length === 0 && (
                <div className="p-4 rounded-lg border border-slate-700 bg-slate-800/40 text-slate-500 text-sm">
                  No technique data available yet.
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-fuchsia-400" />
              Priority Gap Tracker
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {(coverage?.priority_gaps || []).map((gap) => (
              <div key={gap.technique} className="p-3 rounded-lg border border-slate-700 bg-slate-800/40">
                <div className="flex items-center justify-between">
                  <p className="text-white font-medium">{gap.technique}</p>
                  <Badge
                    variant="outline"
                    className={
                      gap.status === 'covered'
                        ? 'text-green-400 border-green-500/30'
                        : gap.status === 'partial'
                        ? 'text-amber-400 border-amber-500/30'
                        : 'text-red-400 border-red-500/30'
                    }
                  >
                    {gap.status}
                  </Badge>
                </div>
                <p className="text-slate-400 text-xs mt-1">{gap.name}</p>
                <p className="text-slate-500 text-xs mt-1">Current depth score: {gap.score}</p>
              </div>
            ))}
            {(coverage?.priority_gaps || []).length === 0 && (
              <div className="p-4 rounded-lg border border-slate-700 bg-slate-800/40 text-slate-500 text-sm">
                No priority gap data returned.
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-fuchsia-400" />
            Depth Score Legend
          </CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2 text-sm">
          <p className="text-red-400">S0: No telemetry source</p>
          <p className="text-orange-400">S1: Telemetry ingested only</p>
          <p className="text-amber-400">S2: Rule or logic exists</p>
          <p className="text-cyan-400">S3: High-fidelity detection in production</p>
          <p className="text-green-400">S4: Validated with adversary emulation</p>
          <p className="text-slate-300">S5: Automated SOAR response linked</p>
        </CardContent>
      </Card>
    </div>
  );
};

export default MitreAttackCoveragePage;
