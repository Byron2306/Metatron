import { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { Shield, RefreshCw, Search, CheckCircle, AlertTriangle, Database } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Textarea } from '../components/ui/textarea';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const defaultEvent = {
  Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
  CommandLine: 'powershell -enc SQBtAFAAbwB3AGUAcgBTAGgAZQBsAGwA',
  User: 'ACME\\jdoe',
  Hostname: 'DESKTOP-01'
};

const SigmaPage = () => {
  const { token } = useAuth();
  const [status, setStatus] = useState(null);
  const [coverage, setCoverage] = useState(null);
  const [rules, setRules] = useState([]);
  const [ruleQuery, setRuleQuery] = useState('');
  const [eventText, setEventText] = useState(JSON.stringify(defaultEvent, null, 2));
  const [evaluation, setEvaluation] = useState(null);
  const [loadingEval, setLoadingEval] = useState(false);
  const [reloading, setReloading] = useState(false);

  const headers = useMemo(() => ({ Authorization: `Bearer ${token}` }), [token]);

  const fetchAll = async () => {
    try {
      const [statusRes, coverageRes, rulesRes] = await Promise.all([
        axios.get(`${API}/sigma/status`, { headers }),
        axios.get(`${API}/sigma/coverage`, { headers }),
        axios.get(`${API}/sigma/rules?limit=25`, { headers }),
      ]);
      setStatus(statusRes.data);
      setCoverage(coverageRes.data);
      setRules(rulesRes.data.rules || []);
    } catch (err) {
      toast.error('Failed to fetch Sigma data');
    }
  };

  useEffect(() => {
    if (token) {
      fetchAll();
    }
  }, [token]);

  const searchRules = async () => {
    try {
      const res = await axios.get(`${API}/sigma/rules?limit=50&query=${encodeURIComponent(ruleQuery)}`, { headers });
      setRules(res.data.rules || []);
    } catch (err) {
      toast.error('Failed to query Sigma rules');
    }
  };

  const reloadRules = async () => {
    setReloading(true);
    try {
      const res = await axios.post(`${API}/sigma/reload`, {}, { headers });
      toast.success(`Reloaded ${res.data.loaded || 0} Sigma rules`);
      await fetchAll();
    } catch (err) {
      toast.error('Failed to reload Sigma rules');
    } finally {
      setReloading(false);
    }
  };

  const evaluateEvent = async () => {
    setLoadingEval(true);
    try {
      const parsedEvent = JSON.parse(eventText);
      const res = await axios.post(
        `${API}/sigma/evaluate`,
        { event: parsedEvent, max_matches: 25 },
        { headers }
      );
      setEvaluation(res.data);
      if (res.data.matches_found > 0) {
        toast.warning(`Sigma matched ${res.data.matches_found} rule(s)`);
      } else {
        toast.success('No Sigma rule matched this event');
      }
    } catch (err) {
      toast.error('Invalid event JSON or Sigma evaluation failed');
    } finally {
      setLoadingEval(false);
    }
  };

  return (
    <div className="space-y-6" data-testid="sigma-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-cyan-400" />
            Sigma Detection Engine
          </h1>
          <p className="text-slate-400 text-sm mt-1">Backend Sigma rule coverage and real-time event matching</p>
        </div>
        <Button
          onClick={reloadRules}
          disabled={reloading}
          variant="outline"
          className="border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/10"
        >
          <RefreshCw className={`w-4 h-4 mr-2 ${reloading ? 'animate-spin' : ''}`} />
          {reloading ? 'Reloading...' : 'Reload Rules'}
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Rules Loaded</p>
          <p className="text-2xl font-bold text-white">{status?.rules_loaded || 0}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">ATT&CK Techniques</p>
          <p className="text-2xl font-bold text-white">{coverage?.technique_count || 0}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Rules Path</p>
          <p className="text-sm font-mono text-cyan-300 truncate">{status?.rules_path || 'n/a'}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Last Reload</p>
          <p className="text-sm text-white">{status?.last_reload ? new Date(status.last_reload).toLocaleString() : 'n/a'}</p>
        </motion.div>
      </div>

      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Search className="w-5 h-5 text-cyan-400" />
            Evaluate Event Against Sigma Rules
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <Textarea
            value={eventText}
            onChange={(e) => setEventText(e.target.value)}
            className="bg-slate-800 border-slate-700 text-white min-h-[180px] font-mono text-xs"
          />
          <Button onClick={evaluateEvent} disabled={loadingEval} className="bg-cyan-600 hover:bg-cyan-700 text-white">
            {loadingEval ? 'Evaluating...' : 'Evaluate Event'}
          </Button>

          {evaluation && (
            <div className="space-y-2">
              <p className="text-slate-300 text-sm">
                Evaluated {evaluation.rules_evaluated} rule(s), matches: {evaluation.matches_found}
              </p>
              <div className="space-y-2 max-h-72 overflow-y-auto">
                {(evaluation.matches || []).map((match) => (
                  <div key={match.id} className="p-3 bg-slate-800/60 border border-slate-700 rounded-lg">
                    <div className="flex items-center justify-between gap-3">
                      <p className="text-white font-medium">{match.title}</p>
                      <Badge variant="outline" className="text-amber-400 border-amber-500/30">{match.level}</Badge>
                    </div>
                    <p className="text-slate-400 text-xs mt-1">{match.source_file}</p>
                    <div className="flex flex-wrap gap-2 mt-2">
                      {(match.attack_techniques || []).map((technique) => (
                        <Badge key={technique} variant="outline" className="text-cyan-300 border-cyan-500/30">{technique}</Badge>
                      ))}
                    </div>
                  </div>
                ))}
                {evaluation.matches_found === 0 && (
                  <div className="p-4 bg-slate-800/40 border border-slate-700 rounded-lg flex items-center gap-2 text-green-400 text-sm">
                    <CheckCircle className="w-4 h-4" />
                    No rule matched the supplied event.
                  </div>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Database className="w-5 h-5 text-cyan-400" />
            Sigma Rule Catalog
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-3">
            <Input
              value={ruleQuery}
              onChange={(e) => setRuleQuery(e.target.value)}
              placeholder="Search by title, description, ATT&CK (e.g. T1059.001)"
              className="bg-slate-800 border-slate-700 text-white"
            />
            <Button onClick={searchRules} variant="outline" className="border-cyan-500/40 text-cyan-300">
              Search
            </Button>
          </div>

          <div className="space-y-2 max-h-96 overflow-y-auto">
            {rules.map((rule) => (
              <div key={rule.id} className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-white font-medium">{rule.title}</p>
                  <Badge variant="outline" className="text-slate-300 border-slate-500/30">{rule.level}</Badge>
                </div>
                <p className="text-slate-500 text-xs mt-1">{rule.source_file}</p>
                <div className="flex flex-wrap gap-2 mt-2">
                  {(rule.attack_techniques || []).slice(0, 8).map((technique) => (
                    <Badge key={technique} variant="outline" className="text-cyan-300 border-cyan-500/30">{technique}</Badge>
                  ))}
                </div>
              </div>
            ))}
            {rules.length === 0 && (
              <div className="p-4 bg-slate-800/40 border border-slate-700 rounded-lg flex items-center gap-2 text-amber-400 text-sm">
                <AlertTriangle className="w-4 h-4" />
                No Sigma rules loaded or matching your query.
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default SigmaPage;
