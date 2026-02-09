import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Crosshair, 
  Search, 
  Brain, 
  Shield,
  AlertTriangle,
  Eye,
  CheckCircle,
  XCircle,
  Clock,
  Zap,
  RefreshCw,
  ChevronRight
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { ScrollArea } from '../components/ui/scroll-area';
import { Progress } from '../components/ui/progress';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select';
import { toast } from 'sonner';

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const categoryIcons = {
  ai_behavior: Brain,
  malware: Shield,
  lateral_movement: Crosshair,
  data_exfil: AlertTriangle,
  persistence: Eye
};

const categoryColors = {
  ai_behavior: 'purple',
  malware: 'red',
  lateral_movement: 'amber',
  data_exfil: 'cyan',
  persistence: 'green'
};

const HypothesisCard = ({ hypothesis, onStatusChange }) => {
  const Icon = categoryIcons[hypothesis.category] || AlertTriangle;
  const color = categoryColors[hypothesis.category] || 'blue';

  const statusConfig = {
    pending: { color: 'slate', icon: Clock, label: 'Pending' },
    investigating: { color: 'amber', icon: Search, label: 'Investigating' },
    confirmed: { color: 'red', icon: CheckCircle, label: 'Confirmed' },
    dismissed: { color: 'green', icon: XCircle, label: 'Dismissed' }
  };

  const status = statusConfig[hypothesis.status] || statusConfig.pending;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded overflow-hidden hover:border-slate-700 transition-all"
    >
      {/* Header */}
      <div className={`p-4 bg-${color}-500/10 border-b border-slate-800`}>
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3">
            <div className={`w-10 h-10 rounded bg-${color}-500/20 flex items-center justify-center`}>
              <Icon className={`w-5 h-5 text-${color}-400`} />
            </div>
            <div>
              <h3 className="font-medium text-white">{hypothesis.title}</h3>
              <div className="flex items-center gap-2 mt-1">
                <Badge variant="outline" className={`text-${color}-400 border-${color}-500/50 text-xs capitalize`}>
                  {hypothesis.category.replace('_', ' ')}
                </Badge>
                <Badge variant="outline" className={`text-${status.color}-400 border-${status.color}-500/50 text-xs`}>
                  <status.icon className="w-3 h-3 mr-1" />
                  {status.label}
                </Badge>
              </div>
            </div>
          </div>
          <div className="text-right">
            <p className="text-xs text-slate-500">Confidence</p>
            <p className={`text-lg font-mono font-bold text-${hypothesis.confidence >= 70 ? 'green' : hypothesis.confidence >= 50 ? 'amber' : 'slate'}-400`}>
              {hypothesis.confidence.toFixed(0)}%
            </p>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="p-4 space-y-4">
        <p className="text-sm text-slate-400">{hypothesis.description}</p>

        {/* Confidence Bar */}
        <div>
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-slate-500">Confidence Level</span>
            <span className="text-xs text-slate-400">{hypothesis.confidence.toFixed(0)}%</span>
          </div>
          <Progress value={hypothesis.confidence} className="h-2" />
        </div>

        {/* Indicators */}
        <div>
          <p className="text-xs text-slate-500 mb-2">Hunt Indicators</p>
          <div className="flex flex-wrap gap-1">
            {hypothesis.indicators.slice(0, 4).map((indicator, i) => (
              <Badge key={i} variant="outline" className="text-xs text-slate-400 border-slate-700">
                {indicator}
              </Badge>
            ))}
          </div>
        </div>

        {/* Recommended Actions */}
        <div>
          <p className="text-xs text-slate-500 mb-2">Recommended Actions</p>
          <ul className="space-y-1">
            {hypothesis.recommended_actions.slice(0, 3).map((action, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-slate-400">
                <ChevronRight className="w-3 h-3 mt-0.5 text-blue-400 flex-shrink-0" />
                {action}
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Footer */}
      <div className="p-4 border-t border-slate-800 flex items-center justify-between">
        <span className="text-xs text-slate-500">
          {new Date(hypothesis.created_at).toLocaleString()}
        </span>
        <div className="flex items-center gap-2">
          {hypothesis.status === 'pending' && (
            <Button
              size="sm"
              variant="outline"
              className="text-xs border-amber-700 text-amber-400 hover:bg-amber-500/10"
              onClick={() => onStatusChange(hypothesis.id, 'investigating')}
              data-testid={`investigate-${hypothesis.id}`}
            >
              <Search className="w-3 h-3 mr-1" />
              Investigate
            </Button>
          )}
          {hypothesis.status === 'investigating' && (
            <>
              <Button
                size="sm"
                variant="outline"
                className="text-xs border-red-700 text-red-400 hover:bg-red-500/10"
                onClick={() => onStatusChange(hypothesis.id, 'confirmed')}
                data-testid={`confirm-${hypothesis.id}`}
              >
                <CheckCircle className="w-3 h-3 mr-1" />
                Confirm
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="text-xs border-green-700 text-green-400 hover:bg-green-500/10"
                onClick={() => onStatusChange(hypothesis.id, 'dismissed')}
                data-testid={`dismiss-${hypothesis.id}`}
              >
                <XCircle className="w-3 h-3 mr-1" />
                Dismiss
              </Button>
            </>
          )}
        </div>
      </div>
    </motion.div>
  );
};

const ThreatHuntingPage = () => {
  const { getAuthHeaders } = useAuth();
  const [hypotheses, setHypotheses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [focusArea, setFocusArea] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');

  const fetchHypotheses = async () => {
    try {
      const params = {};
      if (statusFilter !== 'all') params.status = statusFilter;
      
      const response = await axios.get(`${API}/hunting/hypotheses`, {
        headers: getAuthHeaders(),
        params
      });
      setHypotheses(response.data);
    } catch (error) {
      console.error('Failed to fetch hypotheses:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHypotheses();
  }, [statusFilter]);

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const response = await axios.post(
        `${API}/hunting/generate`,
        { focus_area: focusArea === 'all' ? null : focusArea, time_range_hours: 24 },
        { headers: getAuthHeaders() }
      );
      toast.success(`Generated ${response.data.length} hunting hypotheses`);
      fetchHypotheses();
    } catch (error) {
      toast.error('Failed to generate hypotheses');
    } finally {
      setGenerating(false);
    }
  };

  const handleStatusChange = async (hypothesisId, newStatus) => {
    try {
      await axios.patch(
        `${API}/hunting/hypotheses/${hypothesisId}/status?status=${newStatus}`,
        {},
        { headers: getAuthHeaders() }
      );
      toast.success(`Hypothesis ${newStatus}`);
      fetchHypotheses();
    } catch (error) {
      toast.error('Failed to update status');
    }
  };

  const stats = {
    total: hypotheses.length,
    pending: hypotheses.filter(h => h.status === 'pending').length,
    investigating: hypotheses.filter(h => h.status === 'investigating').length,
    confirmed: hypotheses.filter(h => h.status === 'confirmed').length,
    dismissed: hypotheses.filter(h => h.status === 'dismissed').length
  };

  return (
    <div className="p-6 lg:p-8 space-y-6" data-testid="threat-hunting-page">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-mono font-bold text-white flex items-center gap-3">
            <Crosshair className="w-7 h-7 text-purple-400" />
            Threat Hunting
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            AI-powered threat hunting hypothesis generation
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Select value={focusArea} onValueChange={setFocusArea}>
            <SelectTrigger className="w-40 bg-slate-950 border-slate-700" data-testid="focus-area-select">
              <SelectValue placeholder="Focus Area" />
            </SelectTrigger>
            <SelectContent className="bg-slate-900 border-slate-700">
              <SelectItem value="all">All Areas</SelectItem>
              <SelectItem value="ai_agents">AI Agents</SelectItem>
              <SelectItem value="malware">Malware</SelectItem>
              <SelectItem value="network">Network</SelectItem>
            </SelectContent>
          </Select>
          <Button
            onClick={handleGenerate}
            disabled={generating}
            className="bg-purple-600 hover:bg-purple-500 shadow-glow-purple"
            data-testid="generate-hypotheses-btn"
          >
            {generating ? (
              <span className="flex items-center gap-2">
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Generating...
              </span>
            ) : (
              <span className="flex items-center gap-2">
                <Brain className="w-4 h-4" />
                Generate Hypotheses
              </span>
            )}
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { label: 'Total', value: stats.total, color: 'blue' },
          { label: 'Pending', value: stats.pending, color: 'slate' },
          { label: 'Investigating', value: stats.investigating, color: 'amber' },
          { label: 'Confirmed', value: stats.confirmed, color: 'red' },
          { label: 'Dismissed', value: stats.dismissed, color: 'green' }
        ].map((stat, i) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}
            className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-4"
          >
            <p className="text-slate-400 text-sm">{stat.label}</p>
            <p className={`text-2xl font-mono font-bold text-${stat.color}-400`}>{stat.value}</p>
          </motion.div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-4 bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-4">
        <span className="text-sm text-slate-400">Filter by status:</span>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-40 bg-slate-950 border-slate-700" data-testid="status-filter-select">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent className="bg-slate-900 border-slate-700">
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="pending">Pending</SelectItem>
            <SelectItem value="investigating">Investigating</SelectItem>
            <SelectItem value="confirmed">Confirmed</SelectItem>
            <SelectItem value="dismissed">Dismissed</SelectItem>
          </SelectContent>
        </Select>
        <Button
          variant="outline"
          size="sm"
          className="ml-auto border-slate-700 text-slate-400"
          onClick={fetchHypotheses}
          data-testid="refresh-hypotheses-btn"
        >
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Hypotheses Grid */}
      {loading ? (
        <div className="p-12 text-center text-slate-400">
          <div className="w-8 h-8 border-2 border-purple-500/30 border-t-purple-500 rounded-full animate-spin mx-auto mb-4" />
          Loading hypotheses...
        </div>
      ) : hypotheses.length > 0 ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {hypotheses.map((hypothesis) => (
            <HypothesisCard
              key={hypothesis.id}
              hypothesis={hypothesis}
              onStatusChange={handleStatusChange}
            />
          ))}
        </div>
      ) : (
        <div className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-12 text-center">
          <Brain className="w-12 h-12 mx-auto mb-4 text-slate-600" />
          <h3 className="text-lg font-medium text-slate-400 mb-2">No Hypotheses Found</h3>
          <p className="text-sm text-slate-500 mb-4">
            Generate AI-powered hunting hypotheses to discover hidden threats
          </p>
          <Button
            onClick={handleGenerate}
            disabled={generating}
            className="bg-purple-600 hover:bg-purple-500"
            data-testid="generate-empty-btn"
          >
            <Zap className="w-4 h-4 mr-2" />
            Generate Hypotheses
          </Button>
        </div>
      )}
    </div>
  );
};

export default ThreatHuntingPage;
