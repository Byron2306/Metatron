import { useCallback, useEffect, useMemo, useState } from 'react';
import apiClient from '../lib/api';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { Shield, Target, Layers, CheckCircle2, AlertTriangle, RefreshCw } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';

const scoreLabel = (score) => {
  if (score >= 5) return 'SOAR Response';
  if (score >= 4) return 'Validated';
  if (score >= 3) return 'High Fidelity';
  if (score === 2) return 'Detection Logic';
  if (score === 1) return 'Telemetry Only';
  return 'Not Covered';
};

const scoreClass = (score) => {
  if (score >= 5) return 'text-fuchsia-300 border-fuchsia-500/30';
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

  const loadCoverage = useCallback(async (forceRefresh = false) => {
    setLoading(true);
    try {
      const url = forceRefresh ? `/mitre/coverage?refresh=true` : `/mitre/coverage`;
      const res = await apiClient.get(url);
      setCoverage(res.data);
      if (forceRefresh) toast.success('Coverage recomputed from live sources');
    } catch (err) {
      toast.error('Failed to load MITRE ATT&CK coverage');
    } finally {
      setLoading(false);
    }
  }, [headers]);

  const runSoarResponse = useCallback(async (technique) => {
    if (!technique) return;
    try {
      await apiClient.post(`/soar/techniques/${encodeURIComponent(technique)}/respond`, {});
      toast.success(`SOAR response executed for ${technique}`);
      // Update view (does not regenerate TVR bundle; just refreshes API snapshot)
      await loadCoverage(true);
    } catch (err) {
      toast.error(`SOAR response failed for ${technique}`);
    }
  }, [loadCoverage]);

  useEffect(() => {
    if (token) {
      loadCoverage();
    }
  }, [token, loadCoverage]);

  const derived = useMemo(() => {
    const techniques = coverage?.techniques || [];
    const implementedTechniques = Number(coverage?.implemented_techniques ?? techniques.filter((t) => t.implemented).length);
    const operationalObservedTechniques = Number(
      coverage?.operational_observed_techniques ?? techniques.filter((t) => t.operational_evidence).length
    );
    const coveredScoreGte2 = Number(coverage?.covered_score_gte2 ?? techniques.filter((t) => Number(t.score) >= 2).length);
    const coveredScoreGte3 = Number(coverage?.covered_score_gte3 ?? techniques.filter((t) => Number(t.score) >= 3).length);
    const coveredScoreGte4 = Number(coverage?.covered_score_gte4 ?? techniques.filter((t) => Number(t.score) >= 4).length);
    const implementedCoveredScoreGte3 = Number(
      coverage?.implemented_covered_score_gte3 ??
      techniques.filter((t) => t.implemented && Number(t.score) >= 3).length
    );
    const implementedCoveragePercent = implementedTechniques
      ? Number(((implementedCoveredScoreGte3 / implementedTechniques) * 100).toFixed(2))
      : 0;
    const enterpriseCoveragePercent = Number(coverage?.coverage_percent_gte3 ?? 0);
    const enterpriseCoveragePercentGte2 = Number(coverage?.coverage_percent_gte2 ?? 0);
    const operationalCoveragePercent = Number(coverage?.operational_coverage_percent ?? 0);
    const roadmapTarget = Number(coverage?.roadmap_target_techniques || 639);
    const roadmapCoveragePercent = Number(coverage?.roadmap_coverage_percent_gte3 ?? 0);
    const roadmapCoveragePercentGte2 = Number(coverage?.roadmap_coverage_percent_gte2 ?? 0);
    const roadmapReferencedPercent = Number(coverage?.roadmap_referenced_percent ?? 0);
    return {
      roadmapTarget,
      observedTechniques: techniques.length,
      implementedTechniques,
      operationalObservedTechniques,
      coveredScoreGte2,
      coveredScoreGte3,
      coveredScoreGte4,
      implementedCoveredScoreGte3,
      implementedCoveragePercent,
      enterpriseCoveragePercent,
      enterpriseCoveragePercentGte2,
      operationalCoveragePercent,
      roadmapCoveragePercent,
      roadmapCoveragePercentGte2,
      roadmapReferencedPercent,
    };
  }, [coverage]);

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
        <div className="flex gap-2">
          <Button
            onClick={() => loadCoverage(false)}
            variant="outline"
            className="border-slate-600 text-slate-400 hover:bg-slate-800"
            disabled={loading}
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            From Cache
          </Button>
          <Button
            onClick={() => loadCoverage(true)}
            variant="outline"
            className="border-fuchsia-500/50 text-fuchsia-400 hover:bg-fuchsia-500/10"
            disabled={loading}
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Full Recompute
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Roadmap Target Techniques</p>
          <p className="text-2xl font-bold text-white">{derived.roadmapTarget}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Technique IDs Referenced in Code</p>
          <p className="text-2xl font-bold text-white">{derived.implementedTechniques}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.16 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Operational Evidence-backed Techniques</p>
          <p className="text-2xl font-bold text-white">{derived.operationalObservedTechniques}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.24 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">High-Fidelity Techniques (Score &gt;= 3)</p>
          <p className="text-2xl font-bold text-white">{derived.coveredScoreGte3}</p>
        </motion.div>
      </div>


      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Observed Techniques (All Sources)</p>
          <p className="text-xl font-semibold text-white">{derived.observedTechniques}</p>
        </div>
        <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Enterprise Coverage % (&gt;=3, parent-normalized)</p>
          <p className="text-xl font-semibold text-white">{derived.enterpriseCoveragePercent}%</p>
        </div>
        <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Roadmap Coverage % (&gt;=3)</p>
          <p className="text-xl font-semibold text-white">{derived.roadmapCoveragePercent}%</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Enterprise Coverage % (&gt;=2)</p>
          <p className="text-lg font-semibold text-white">{derived.enterpriseCoveragePercentGte2}%</p>
        </div>
        <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Operational Coverage % (Enterprise)</p>
          <p className="text-lg font-semibold text-white">{derived.operationalCoveragePercent}%</p>
        </div>
        <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Roadmap Referenced %</p>
          <p className="text-lg font-semibold text-white">{derived.roadmapReferencedPercent}%</p>
        </div>
        <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Validated Techniques (Score &gt;=4)</p>
          <p className="text-lg font-semibold text-white">{derived.coveredScoreGte4}</p>
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
                  {Number(item?.evidence?.soar_playbook_count || 0) > 0 && (
                    <p className="text-fuchsia-300 text-xs mt-1">
                      SOAR linked: {item.evidence.soar_playbook_count} playbooks, {item.evidence.soar_execution_count || 0} executions
                    </p>
                  )}
                  {Number(item?.tvr_score || 0) >= 5 && !item?.soar_linked && (
                    <div className="flex items-center justify-between gap-2 mt-2">
                      <p className="text-amber-300 text-xs">S5 pending: missing SOAR response evidence</p>
                      <Button
                        onClick={() => runSoarResponse(item.technique)}
                        variant="outline"
                        className="h-7 px-2 border-fuchsia-500/50 text-fuchsia-300 hover:bg-fuchsia-500/10"
                        disabled={loading}
                      >
                        Run SOAR Response
                      </Button>
                    </div>
                  )}
                  {item.operational_evidence && (
                    <p className="text-indigo-300 text-xs mt-1">Operational evidence observed</p>
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
          <p className="text-fuchsia-300">S5: Validated + automated SOAR response linked</p>
        </CardContent>
      </Card>
    </div>
  );
};

export default MitreAttackCoveragePage;
