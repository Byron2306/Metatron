import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Bell, 
  AlertTriangle, 
  CheckCircle, 
  Eye,
  Filter,
  Clock,
  Shield,
  Zap
} from 'lucide-react';
import { Button } from '../components/ui/button';
import SeraphPageHeader from '../components/SeraphPageHeader';
import { Badge } from '../components/ui/badge';
import { ScrollArea } from '../components/ui/scroll-area';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const AlertCard = ({ alert, onStatusChange }) => {
  const severityColors = {
    critical: { 
      bg: 'bg-neon-red/10', 
      border: 'border-neon-red/30', 
      text: 'text-neon-red', 
      icon: 'text-neon-red', 
      textHex: '#EF4444', 
      borderHex: 'rgba(239,68,68,0.3)', 
      tint: 'rgba(239,68,68,0.12)' 
    },
    high: { 
      bg: 'bg-neon-amber/10', 
      border: 'border-neon-amber/30', 
      text: 'text-neon-amber', 
      icon: 'text-neon-amber', 
      textHex: '#F59E0B', 
      borderHex: 'rgba(245,158,11,0.3)', 
      tint: 'rgba(245,158,11,0.11)' 
    },
    medium: { 
      bg: 'bg-neon-cyan/10', 
      border: 'border-neon-cyan/30', 
      text: 'text-neon-cyan', 
      icon: 'text-neon-cyan', 
      textHex: '#06B6D4', 
      borderHex: 'rgba(6,182,212,0.3)', 
      tint: 'rgba(6,182,212,0.1)' 
    },
    low: { 
      bg: 'bg-neon-green/10', 
      border: 'border-neon-green/30', 
      text: 'text-neon-green', 
      icon: 'text-neon-green', 
      textHex: '#10B981', 
      borderHex: 'rgba(16,185,129,0.3)', 
      tint: 'rgba(16,185,129,0.1)' 
    }
  };

  const colors = severityColors[alert.severity] || severityColors.medium;

  const typeIcons = {
    ai_detected: Zap,
    behavioral: Eye,
    signature: Shield,
    anomaly: AlertTriangle
  };

  const TypeIcon = typeIcons[alert.type] || AlertTriangle;

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      className={`p-5 ${colors.bg} border-l-4 ${colors.border} rounded-r`}
      style={{
        background: `linear-gradient(140deg, ${colors.tint}, rgba(4,11,22,0.92))`,
        borderLeftColor: colors.borderHex,
        boxShadow: `0 0 16px ${colors.tint}`,
      }}
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-start gap-3">
          <div className={`w-10 h-10 rounded flex items-center justify-center ${colors.bg}`}>
            <TypeIcon className={`w-5 h-5 ${colors.icon}`} style={{ color: colors.textHex }} />
          </div>
          <div>
            <div className="font-medium" style={{ color: '#e6fbff' }}>{alert.title}</div>
            <div className="flex items-center gap-2 mt-1">
              <Badge variant="outline" className={`${colors.text} ${colors.border} text-xs`} style={{ color: colors.textHex }}>
                {alert.severity}
              </Badge>
              <Badge variant="outline" className="text-slate-400 border-slate-600 text-xs">
                {alert.type.replace('_', ' ')}
              </Badge>
            </div>
          </div>
        </div>
        <div className="text-right">
          <span className={`text-xs px-2 py-1 rounded ${
            alert.status === 'new' ? 'bg-blue-500/20 text-blue-400' :
            alert.status === 'acknowledged' ? 'bg-amber-500/20 text-amber-400' :
            'bg-green-500/20 text-green-400'
          }`}>
            {alert.status}
          </span>
        </div>
      </div>

      <p className="text-sm text-slate-400 mb-4">{alert.message}</p>

      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <Clock className="w-3 h-3" />
          {new Date(alert.created_at).toLocaleString()}
        </div>
        <div className="flex items-center gap-2">
          {alert.status === 'new' && (
            <Button
              size="sm"
              variant="outline"
              className="text-xs border-slate-700 text-slate-300 hover:bg-slate-800"
              onClick={() => onStatusChange(alert.id, 'acknowledged')}
              data-testid={`acknowledge-alert-${alert.id}`}
            >
              <Eye className="w-3 h-3 mr-1" />
              Acknowledge
            </Button>
          )}
          {alert.status !== 'resolved' && (
            <Button
              size="sm"
              variant="outline"
              className="text-xs border-green-700 text-green-400 hover:bg-green-500/10"
              onClick={() => onStatusChange(alert.id, 'resolved')}
              data-testid={`resolve-alert-${alert.id}`}
            >
              <CheckCircle className="w-3 h-3 mr-1" />
              Resolve
            </Button>
          )}
        </div>
      </div>
    </motion.div>
  );
};

const AlertsPage = () => {
  const { getAuthHeaders } = useAuth();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');

  const fetchAlerts = async () => {
    try {
      const params = {};
      if (statusFilter !== 'all') params.status = statusFilter;
      
      const response = await axios.get(`${API}/alerts`, {
        headers: getAuthHeaders(),
        params
      });
      // Handle both array and object response formats
      const alertsData = Array.isArray(response.data) 
        ? response.data 
        : (response.data.alerts || []);
      setAlerts(alertsData);
    } catch (error) {
      toast.error('Failed to fetch alerts');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const id = setInterval(fetchAlerts, 10000);
    return () => clearInterval(id);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter]);

  const handleStatusChange = async (alertId, newStatus) => {
    try {
      await axios.patch(
        `${API}/alerts/${alertId}/status?status=${newStatus}`,
        {},
        { headers: getAuthHeaders() }
      );
      toast.success(`Alert ${newStatus}`);
      fetchAlerts();
    } catch (error) {
      toast.error('Failed to update alert');
    }
  };

  const filteredAlerts = alerts.filter(alert => {
    if (severityFilter !== 'all' && alert.severity !== severityFilter) return false;
    return true;
  });

  const alertStats = {
    total: alerts.length,
    new: alerts.filter(a => a.status === 'new').length,
    acknowledged: alerts.filter(a => a.status === 'acknowledged').length,
    resolved: alerts.filter(a => a.status === 'resolved').length,
    critical: alerts.filter(a => a.severity === 'critical' && a.status !== 'resolved').length
  };

  return (
    <div className="p-6 lg:p-8 space-y-6" data-testid="alerts-page">
      <SeraphPageHeader
        eyebrow="seraph · alerts · siem stream"
        title={<span className="seraph-heading-flood-rtl">Alert Management</span>}
        tagline="> live correlation · severity triage · response routing"
        accent={alertStats.critical > 0 ? 'pink' : 'cyan'}
        status={alertStats.critical > 0 ? `${alertStats.critical} CRITICAL` : 'NOMINAL'}
      />

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Alerts', value: alertStats.total, color: 'blue' },
          { label: 'New', value: alertStats.new, color: 'cyan' },
          { label: 'Acknowledged', value: alertStats.acknowledged, color: 'amber' },
          { label: 'Resolved', value: alertStats.resolved, color: 'green' }
        ].map((stat, i) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-4"
          >
            <p className="text-slate-400 text-sm">{stat.label}</p>
            <p className={`text-2xl font-mono font-bold text-${stat.color}-400`}>{stat.value}</p>
          </motion.div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4 bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded p-4">
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-slate-400" />
          <span className="text-sm text-slate-400">Filter:</span>
        </div>
        
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-40 bg-slate-950 border-slate-700" data-testid="status-filter">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent className="bg-slate-900 border-slate-700">
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="new">New</SelectItem>
            <SelectItem value="acknowledged">Acknowledged</SelectItem>
            <SelectItem value="resolved">Resolved</SelectItem>
          </SelectContent>
        </Select>

        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-40 bg-slate-950 border-slate-700" data-testid="severity-filter">
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
          size="sm"
          className="ml-auto seraph-btn-primary"
          onClick={fetchAlerts}
          data-testid="refresh-alerts-btn"
        >
          Refresh
        </Button>
      </div>

      {/* Alerts List */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded"
      >
        {loading ? (
          <div className="p-12 text-center text-slate-400">
            <div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin mx-auto mb-4" />
            Loading alerts...
          </div>
        ) : filteredAlerts.length > 0 ? (
          <ScrollArea className="h-[600px]">
            <div className="p-4 space-y-4">
              {filteredAlerts.map((alert, i) => (
                <AlertCard 
                  key={alert.id} 
                  alert={alert} 
                  onStatusChange={handleStatusChange}
                />
              ))}
            </div>
          </ScrollArea>
        ) : (
          <div className="p-12 text-center">
            <Bell className="w-12 h-12 mx-auto mb-4 text-slate-600" />
            <h3 className="text-lg font-medium text-slate-400 mb-2">No Alerts Found</h3>
            <p className="text-sm text-slate-500">
              {statusFilter !== 'all' || severityFilter !== 'all' 
                ? 'Try adjusting your filters' 
                : 'System is clear of alerts'}
            </p>
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default AlertsPage;
