import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  AlertTriangle, 
  Shield, 
  Target,
  Plus,
  Filter,
  Clock,
  Server,
  Globe,
  Bug,
  Bot,
  Network,
  Mail
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Textarea } from '../components/ui/textarea';
import SeraphPageHeader from '../components/SeraphPageHeader';
import { ScrollArea } from '../components/ui/scroll-area';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogDescription,
} from '../components/ui/dialog';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const THREAT_ACCENTS = {
  critical: { border: '#ff35f4', glow: 'rgba(255,43,214,0.42)', surface: 'rgba(46,8,38,0.78)', text: '#ffd1f8', badge: 'bg-pink-500/16 text-pink-200 border-pink-400/55' },
  high: { border: '#bc13fe', glow: 'rgba(188,19,254,0.38)', surface: 'rgba(28,8,46,0.78)', text: '#efddff', badge: 'bg-purple-500/16 text-purple-200 border-purple-400/55' },
  medium: { border: '#00f6ff', glow: 'rgba(0,240,255,0.36)', surface: 'rgba(8,26,38,0.80)', text: '#c8fbff', badge: 'bg-cyan-500/16 text-cyan-200 border-cyan-400/55' },
  low: { border: '#39ff14', glow: 'rgba(57,255,20,0.34)', surface: 'rgba(8,36,18,0.76)', text: '#d4ffe2', badge: 'bg-green-500/16 text-green-200 border-green-400/55' },
  info: { border: '#00f6ff', glow: 'rgba(0,240,255,0.32)', surface: 'rgba(8,22,38,0.82)', text: '#c8f6ff', badge: 'bg-cyan-500/16 text-cyan-200 border-cyan-400/55' },
};

const threatPanelStyle = (accent) => ({
  background: `
    linear-gradient(rgba(0,0,0,0) 50%, rgba(0,0,0,0.32) 50%),
    linear-gradient(90deg, rgba(255,43,214,0.05), rgba(0,240,255,0.07), rgba(57,255,20,0.035)),
    linear-gradient(160deg, rgba(8,18,34,0.94), rgba(3,9,18,0.97))
  `,
  backgroundSize: '100% 3px, 100% 100%, 100% 100%',
  border: `3px solid ${accent.border}`,
  boxShadow: `0 0 34px ${accent.glow}, inset 0 0 22px rgba(0,240,255,0.07), inset 0 0 36px ${accent.glow}`,
  clipPath: 'polygon(12px 0, 100% 0, 100% calc(100% - 12px), calc(100% - 12px) 100%, 0 100%, 0 12px)',
});

const threatActionStyle = (accent, filled = false) => ({
  background: filled ? `linear-gradient(135deg, ${accent.border}, rgba(255,255,255,0.08))` : 'linear-gradient(135deg, rgba(8,20,38,0.88), rgba(4,11,22,0.94))',
  border: `2px solid ${accent.border}`,
  color: filled ? '#07111e' : accent.text,
  boxShadow: `0 0 16px ${accent.glow}`,
  clipPath: 'polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px)',
});

const ThreatTypeIcon = ({ type }) => {
  const icons = {
    ai_agent: Bot,
    malware: Bug,
    botnet: Network,
    phishing: Mail,
    ransomware: Shield
  };
  const Icon = icons[type] || AlertTriangle;
  return <Icon className="w-5 h-5" />;
};

const ThreatCard = ({ threat, onStatusChange }) => {
  const severityColors = {
    critical: THREAT_ACCENTS.critical,
    high: THREAT_ACCENTS.high,
    medium: THREAT_ACCENTS.medium,
    low: THREAT_ACCENTS.low
  };

  const statusColors = {
    active: 'bg-pink-500/20 text-pink-300',
    contained: 'bg-purple-500/20 text-purple-200',
    resolved: 'bg-green-500/20 text-green-400'
  };

  const colors = severityColors[threat.severity] || severityColors.medium;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="overflow-hidden transition-all duration-300 sophia-scan sophia-edge-sweep sophia-panel-glow"
      style={threatPanelStyle(colors)}
    >
      {/* Header */}
      <div className="p-4" style={{ background: `linear-gradient(135deg, ${colors.surface}, rgba(4,11,22,0.88))`, borderBottom: `1px solid ${colors.border}55` }}>
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3">
            <div className="w-10 h-10 rounded flex items-center justify-center" style={{ background: `${colors.border}1f`, border: `1px solid ${colors.border}88`, color: colors.border, boxShadow: `0 0 12px ${colors.glow}` }}>
              <ThreatTypeIcon type={threat.type} />
            </div>
            <div>
              <div className="sophia-flicker sophia-terminal-value text-base" style={{ fontSize: '1rem', color: colors.text }}>{threat.name}</div>
              <div className="flex items-center gap-2 mt-1">
                <Badge variant="outline" className={`${colors.badge} text-xs`} style={{ color: colors.text, borderColor: `${colors.border}88` }}>
                  {threat.severity}
                </Badge>
                <Badge variant="outline" className="text-xs sophia-terminal-meta" style={{ borderColor: 'rgba(102,230,255,0.26)', color: '#a8ebff' }}>
                  {threat.type.replace('_', ' ')}
                </Badge>
              </div>
            </div>
          </div>
          <span className={`text-xs px-2 py-1 rounded ${statusColors[threat.status]}`} style={{ border: `1px solid ${colors.border}55`, boxShadow: `0 0 10px ${colors.glow}` }}>
            {threat.status}
          </span>
        </div>
      </div>

      {/* Content */}
      <div className="p-4 space-y-3">
        {threat.description && (
          <p className="sophia-terminal-meta text-sm" style={{ color: '#b5d3de' }}>{threat.description}</p>
        )}

        <div className="grid grid-cols-2 gap-3 text-sm">
          {threat.source_ip && (
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-slate-500" />
              <span className="sophia-terminal-meta">Source: <span className="sophia-flicker sophia-terminal-value text-sm" style={{ fontSize: '0.85rem', color: '#e8fdff' }}>{threat.source_ip}</span></span>
            </div>
          )}
          {threat.target_system && (
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-slate-500" />
              <span className="sophia-terminal-meta">Target: <span className="sophia-flicker sophia-terminal-value text-sm" style={{ fontSize: '0.85rem', color: '#e8fdff' }}>{threat.target_system}</span></span>
            </div>
          )}
        </div>

        {threat.indicators?.length > 0 && (
          <div className="pt-2">
            <p className="sophia-scan sophia-terminal-label text-xs mb-2">Indicators</p>
            <div className="flex flex-wrap gap-1">
              {threat.indicators.map((indicator, i) => (
                <Badge key={i} variant="outline" className="text-xs" style={{ color: '#a8ebff', borderColor: `${colors.border}66`, background: `${colors.border}12` }}>
                  {indicator}
                </Badge>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="p-4 flex items-center justify-between" style={{ borderTop: `1px solid ${colors.border}44` }}>
        <div className="flex items-center gap-2 sophia-terminal-meta text-xs">
          <Clock className="w-3 h-3" />
          {new Date(threat.created_at).toLocaleString()}
        </div>
        <div className="flex items-center gap-2">
          {threat.status === 'active' && (
            <Button
              size="sm"
              variant="outline"
              className="text-xs"
              style={threatActionStyle(THREAT_ACCENTS.high)}
              onClick={() => onStatusChange(threat.id, 'contained')}
              data-testid={`contain-threat-${threat.id}`}
            >
              <Target className="w-3 h-3 mr-1" />
              Contain
            </Button>
          )}
          {threat.status !== 'resolved' && (
            <Button
              size="sm"
              variant="outline"
              className="text-xs"
              style={threatActionStyle(THREAT_ACCENTS.low)}
              onClick={() => onStatusChange(threat.id, 'resolved')}
              data-testid={`resolve-threat-${threat.id}`}
            >
              <Shield className="w-3 h-3 mr-1" />
              Resolve
            </Button>
          )}
        </div>
      </div>
    </motion.div>
  );
};

const ThreatsPage = () => {
  const { getAuthHeaders } = useAuth();
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [newThreat, setNewThreat] = useState({
    name: '',
    type: 'ai_agent',
    severity: 'high',
    source_ip: '',
    target_system: '',
    description: '',
    indicators: []
  });

  const fetchThreats = async () => {
    try {
      const params = {};
      if (statusFilter !== 'all') params.status = statusFilter;
      if (severityFilter !== 'all') params.severity = severityFilter;
      
      const response = await axios.get(`${API}/threats`, {
        headers: getAuthHeaders(),
        params
      });
      setThreats(response.data);
    } catch (error) {
      toast.error('Failed to fetch threats');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
    const id = setInterval(fetchThreats, 10000);
    return () => clearInterval(id);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter, severityFilter]);

  const handleStatusChange = async (threatId, newStatus) => {
    try {
      await axios.patch(
        `${API}/threats/${threatId}/status?status=${newStatus}`,
        {},
        { headers: getAuthHeaders() }
      );
      toast.success(`Threat ${newStatus}`);
      fetchThreats();
    } catch (error) {
      toast.error('Failed to update threat');
    }
  };

  const handleAddThreat = async () => {
    try {
      await axios.post(`${API}/threats`, newThreat, {
        headers: getAuthHeaders()
      });
      toast.success('Threat logged successfully');
      setShowAddDialog(false);
      setNewThreat({
        name: '',
        type: 'ai_agent',
        severity: 'high',
        source_ip: '',
        target_system: '',
        description: '',
        indicators: []
      });
      fetchThreats();
    } catch (error) {
      toast.error('Failed to add threat');
    }
  };

  const threatStats = {
    total: threats.length,
    active: threats.filter(t => t.status === 'active').length,
    contained: threats.filter(t => t.status === 'contained').length,
    resolved: threats.filter(t => t.status === 'resolved').length
  };

  return (
    <div className="p-6 lg:p-8 space-y-6" data-testid="threats-page" data-accent="magenta">
      <SeraphPageHeader
        eyebrow="seraph · threats · adversary tracking"
        title={<span className="seraph-heading-flood-rtl">Threat Management</span>}
        tagline="> tracked threats · attribution · response status"
        accent="pink"
        status={threatStats.active ? `${threatStats.active} ACTIVE` : 'CLEAR'}
      />
      <div className="flex justify-end">
        <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
          <DialogTrigger asChild>
            <Button
              style={threatActionStyle(THREAT_ACCENTS.info, true)}
              onClick={() => setShowAddDialog(true)}
              data-testid="add-threat-btn"
            >
              <Plus className="w-4 h-4 mr-2" />
              Log Threat
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-md sophia-scan" style={threatPanelStyle(THREAT_ACCENTS.info)}>
            <DialogHeader>
              <DialogTitle className="sophia-terminal-heading">Log New Threat</DialogTitle>
              <DialogDescription className="sophia-terminal-meta">
                Enter details about the detected threat
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 pt-4">
              <div>
                <Label className="sophia-scan sophia-terminal-label">Threat Name</Label>
                <Input
                  value={newThreat.name}
                  onChange={(e) => setNewThreat({ ...newThreat, name: e.target.value })}
                  className="text-white"
                  style={{ background: 'rgba(3,9,18,0.92)', borderColor: 'rgba(102,230,255,0.26)' }}
                  placeholder="e.g., Suspicious AI Agent Activity"
                  data-testid="threat-name-input"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="sophia-scan sophia-terminal-label">Type</Label>
                  <Select value={newThreat.type} onValueChange={(v) => setNewThreat({ ...newThreat, type: v })}>
                    <SelectTrigger className="text-white" style={{ background: 'rgba(3,9,18,0.92)', borderColor: 'rgba(102,230,255,0.26)' }} data-testid="threat-type-select">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-900 border-slate-700">
                      <SelectItem value="ai_agent">AI Agent</SelectItem>
                      <SelectItem value="malware">Malware</SelectItem>
                      <SelectItem value="botnet">Botnet</SelectItem>
                      <SelectItem value="phishing">Phishing</SelectItem>
                      <SelectItem value="ransomware">Ransomware</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label className="sophia-scan sophia-terminal-label">Severity</Label>
                  <Select value={newThreat.severity} onValueChange={(v) => setNewThreat({ ...newThreat, severity: v })}>
                    <SelectTrigger className="text-white" style={{ background: 'rgba(3,9,18,0.92)', borderColor: 'rgba(102,230,255,0.26)' }} data-testid="threat-severity-select">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-900 border-slate-700">
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div>
                <Label className="sophia-scan sophia-terminal-label">Source IP</Label>
                <Input
                  value={newThreat.source_ip}
                  onChange={(e) => setNewThreat({ ...newThreat, source_ip: e.target.value })}
                  className="text-white"
                  style={{ background: 'rgba(3,9,18,0.92)', borderColor: 'rgba(102,230,255,0.26)' }}
                  placeholder="e.g., 192.168.1.100"
                  data-testid="threat-ip-input"
                />
              </div>
              <div>
                <Label className="sophia-scan sophia-terminal-label">Target System</Label>
                <Input
                  value={newThreat.target_system}
                  onChange={(e) => setNewThreat({ ...newThreat, target_system: e.target.value })}
                  className="text-white"
                  style={{ background: 'rgba(3,9,18,0.92)', borderColor: 'rgba(102,230,255,0.26)' }}
                  placeholder="e.g., Production Server"
                  data-testid="threat-target-input"
                />
              </div>
              <div>
                <Label className="sophia-scan sophia-terminal-label">Description</Label>
                <Textarea
                  value={newThreat.description}
                  onChange={(e) => setNewThreat({ ...newThreat, description: e.target.value })}
                  className="text-white"
                  style={{ background: 'rgba(3,9,18,0.92)', borderColor: 'rgba(102,230,255,0.26)' }}
                  placeholder="Describe the threat..."
                  data-testid="threat-description-input"
                />
              </div>
              <Button 
                onClick={handleAddThreat} 
                className="w-full"
                style={threatActionStyle(THREAT_ACCENTS.info, true)}
                disabled={!newThreat.name}
                data-testid="submit-threat-btn"
              >
                Log Threat
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Threats', value: threatStats.total, accent: THREAT_ACCENTS.info },
          { label: 'Active', value: threatStats.active, accent: THREAT_ACCENTS.critical },
          { label: 'Contained', value: threatStats.contained, accent: THREAT_ACCENTS.high },
          { label: 'Resolved', value: threatStats.resolved, accent: THREAT_ACCENTS.low }
        ].map((stat, i) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            className="sophia-scan p-4"
            style={threatPanelStyle(stat.accent)}
          >
            <p className="sophia-terminal-label text-sm">{stat.label}</p>
            <p className="sophia-flicker sophia-terminal-value text-2xl font-bold" style={{ color: stat.accent.text, textShadow: `0 0 14px ${stat.accent.glow}` }}>{stat.value}</p>
          </motion.div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4 p-4 sophia-scan" style={threatPanelStyle(THREAT_ACCENTS.info)}>
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-slate-400" />
          <span className="sophia-terminal-label text-sm">Filter</span>
        </div>
        
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-40 text-white" style={{ background: 'rgba(3,9,18,0.92)', borderColor: 'rgba(102,230,255,0.26)' }} data-testid="threat-status-filter">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent className="bg-slate-900 border-slate-700">
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="active">Active</SelectItem>
            <SelectItem value="contained">Contained</SelectItem>
            <SelectItem value="resolved">Resolved</SelectItem>
          </SelectContent>
        </Select>

        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-40 text-white" style={{ background: 'rgba(3,9,18,0.92)', borderColor: 'rgba(102,230,255,0.26)' }} data-testid="threat-severity-filter">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent className="bg-slate-900 border-slate-700">
            <SelectItem value="all">All Severity</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>

        <Button
          variant="outline"
          size="sm"
          className="ml-auto"
          style={threatActionStyle(THREAT_ACCENTS.info)}
          onClick={fetchThreats}
          data-testid="refresh-threats-btn"
        >
          Refresh
        </Button>
      </div>

      {/* Threats Grid */}
      {loading ? (
        <div className="p-12 text-center text-slate-400">
          <div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin mx-auto mb-4" />
          Loading threats...
        </div>
      ) : threats.length > 0 ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {threats.map((threat) => (
            <ThreatCard 
              key={threat.id} 
              threat={threat} 
              onStatusChange={handleStatusChange}
            />
          ))}
        </div>
      ) : (
        <div className="p-12 text-center sophia-scan" style={threatPanelStyle(THREAT_ACCENTS.low)}>
          <Shield className="w-12 h-12 mx-auto mb-4" style={{ color: THREAT_ACCENTS.low.border, filter: 'drop-shadow(0 0 8px rgba(141,255,179,0.44))' }} />
          <h3 className="sophia-terminal-heading text-lg mb-2">No Threats Found</h3>
          <p className="sophia-terminal-meta text-sm">
            {statusFilter !== 'all' || severityFilter !== 'all' 
              ? 'Try adjusting your filters' 
              : 'System is secure - no threats detected'}
          </p>
        </div>
      )}
    </div>
  );
};

export default ThreatsPage;
