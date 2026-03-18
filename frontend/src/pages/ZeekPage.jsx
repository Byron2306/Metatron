import { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { Radar, RefreshCw, Activity, Database, AlertTriangle, Search, Network } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const ZeekPage = () => {
  const { token } = useAuth();
  const [status, setStatus] = useState(null);
  const [stats, setStats] = useState(null);
  const [logTypes, setLogTypes] = useState([]);
  const [selectedLog, setSelectedLog] = useState('conn');
  const [records, setRecords] = useState([]);
  const [beaconing, setBeaconing] = useState([]);
  const [dnsTunneling, setDnsTunneling] = useState([]);
  const [limit, setLimit] = useState('50');
  const [loading, setLoading] = useState(false);

  const headers = useMemo(() => ({ Authorization: `Bearer ${token}` }), [token]);

  const fetchOverview = async () => {
    try {
      const [statusRes, statsRes, typesRes] = await Promise.all([
        axios.get(`${API}/zeek/status`, { headers }),
        axios.get(`${API}/zeek/stats`, { headers }),
        axios.get(`${API}/zeek/log-types`, { headers }),
      ]);
      setStatus(statusRes.data);
      setStats(statsRes.data);
      setLogTypes(typesRes.data.discovered || typesRes.data.defaults || []);
    } catch (err) {
      toast.error('Failed to load Zeek overview');
    }
  };

  const fetchRecords = async () => {
    setLoading(true);
    try {
      const lim = Number.parseInt(limit, 10) || 50;
      const res = await axios.get(`${API}/zeek/logs/${selectedLog}?limit=${lim}`, { headers });
      setRecords(res.data.records || []);
      if (res.data.message) {
        toast.info(res.data.message);
      }
    } catch (err) {
      toast.error('Failed to load Zeek records');
    } finally {
      setLoading(false);
    }
  };

  const fetchDetections = async () => {
    try {
      const [beaconRes, dnsRes] = await Promise.all([
        axios.get(`${API}/zeek/detections/beaconing?limit=20`, { headers }),
        axios.get(`${API}/zeek/detections/dns-tunneling?limit=20`, { headers }),
      ]);
      setBeaconing(beaconRes.data.detections || []);
      setDnsTunneling(dnsRes.data.detections || []);
    } catch (err) {
      toast.error('Failed to load Zeek detections');
    }
  };

  useEffect(() => {
    if (token) {
      fetchOverview();
      fetchRecords();
      fetchDetections();
    }
  }, [token]);

  const refreshAll = async () => {
    await Promise.all([fetchOverview(), fetchRecords(), fetchDetections()]);
  };

  return (
    <div className="space-y-6" data-testid="zeek-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Radar className="w-6 h-6 text-cyan-400" />
            Zeek NDR Integration
          </h1>
          <p className="text-slate-400 text-sm mt-1">Network telemetry from Zeek logs, mapped into backend analytics</p>
        </div>
        <Button onClick={refreshAll} variant="outline" className="border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/10">
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Zeek Available</p>
          <p className={`text-2xl font-bold ${status?.available ? 'text-green-400' : 'text-amber-400'}`}>{status?.available ? 'Yes' : 'No'}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Conn Events</p>
          <p className="text-2xl font-bold text-white">{stats?.conn_events || 0}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">DNS Events</p>
          <p className="text-2xl font-bold text-white">{stats?.dns_events || 0}</p>
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <p className="text-slate-400 text-sm">Sources</p>
          <p className="text-2xl font-bold text-white">{stats?.unique_sources || 0}</p>
        </motion.div>
      </div>

      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Database className="w-5 h-5 text-cyan-400" />
            Zeek Log Records
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2">
              {(logTypes.length > 0 ? logTypes : ['conn', 'dns', 'http', 'ssl']).map((type) => (
                <Button
                  key={type}
                  size="sm"
                  variant={selectedLog === type ? 'default' : 'outline'}
                  onClick={() => setSelectedLog(type)}
                  className={selectedLog === type ? 'bg-cyan-600 hover:bg-cyan-700 text-white' : 'border-slate-600 text-slate-200'}
                >
                  {type}
                </Button>
              ))}
            </div>
            <Input
              value={limit}
              onChange={(e) => setLimit(e.target.value)}
              className="w-24 bg-slate-800 border-slate-700 text-white"
              placeholder="limit"
            />
            <Button onClick={fetchRecords} disabled={loading} variant="outline" className="border-cyan-500/40 text-cyan-300">
              <Search className="w-4 h-4 mr-2" />
              {loading ? 'Loading...' : 'Load Records'}
            </Button>
          </div>

          <div className="space-y-2 max-h-96 overflow-y-auto">
            {records.slice(0, 100).map((rec, idx) => (
              <div key={`${selectedLog}-${idx}`} className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                <pre className="text-xs text-slate-200 overflow-x-auto">{JSON.stringify(rec, null, 2)}</pre>
              </div>
            ))}
            {records.length === 0 && (
              <div className="p-4 bg-slate-800/40 border border-slate-700 rounded-lg flex items-center gap-2 text-amber-400 text-sm">
                <AlertTriangle className="w-4 h-4" />
                No records found for selected log type.
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-amber-400" />
              Beaconing Detections
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 max-h-80 overflow-y-auto">
            {beaconing.map((item, idx) => (
              <div key={`beacon-${idx}`} className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                <p className="text-white text-sm font-medium">{item.src_ip} → {item.dest_ip}</p>
                <div className="flex flex-wrap gap-2 mt-2">
                  <Badge variant="outline" className="text-cyan-300 border-cyan-500/30">events {item.events}</Badge>
                  <Badge variant="outline" className="text-amber-300 border-amber-500/30">avg {item.avg_interval_seconds}s</Badge>
                  <Badge variant="outline" className="text-slate-300 border-slate-500/30">jitter {item.jitter_seconds}s</Badge>
                </div>
              </div>
            ))}
            {beaconing.length === 0 && <p className="text-slate-400 text-sm">No beaconing detections.</p>}
          </CardContent>
        </Card>

        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Network className="w-5 h-5 text-purple-400" />
              DNS Tunneling Heuristics
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 max-h-80 overflow-y-auto">
            {dnsTunneling.map((item, idx) => (
              <div key={`dns-${idx}`} className="p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                <p className="text-white text-sm font-medium">{item.src_ip}</p>
                <div className="flex flex-wrap gap-2 mt-2">
                  <Badge variant="outline" className="text-cyan-300 border-cyan-500/30">queries {item.queries}</Badge>
                  <Badge variant="outline" className="text-purple-300 border-purple-500/30">avg len {item.avg_query_length}</Badge>
                  <Badge variant="outline" className="text-slate-300 border-slate-500/30">unique {item.unique_ratio}</Badge>
                </div>
              </div>
            ))}
            {dnsTunneling.length === 0 && <p className="text-slate-400 text-sm">No DNS tunneling detections.</p>}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default ZeekPage;
