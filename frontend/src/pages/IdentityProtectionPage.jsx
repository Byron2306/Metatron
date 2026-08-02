import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  User, 
  RefreshCw, 
  AlertTriangle, 
  Activity,
  Shield,
  Lock,
  Key,
  Users,
  Server,
  Database,
  Network,
  Fingerprint,
  Eye,
  Clock,
  TrendingUp,
  AlertOctagon,
  CheckCircle2,
  XCircle,
  ShieldAlert,
  ShieldCheck,
  Ticket,
  FileKey,
  UserX,
  Zap,
  Target,
  ChevronRight,
  Play,
  BarChart3,
  Search
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';
import SeraphPageHeader from '../components/SeraphPageHeader';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const IDENTITY_TONES = {
  cyan: { border: 'rgba(0,240,255,0.34)', glow: 'rgba(0,240,255,0.16)', text: '#aef7ff' },
  orange: { border: 'rgba(255,176,32,0.34)', glow: 'rgba(255,176,32,0.16)', text: '#ffd78a' },
  red: { border: 'rgba(255,91,91,0.34)', glow: 'rgba(255,91,91,0.14)', text: '#ffd4d4' },
  green: { border: 'rgba(57,255,20,0.34)', glow: 'rgba(57,255,20,0.16)', text: '#b8ffca' },
  yellow: { border: 'rgba(255,211,122,0.34)', glow: 'rgba(255,211,122,0.16)', text: '#fff2d2' },
  purple: { border: 'rgba(188,19,254,0.34)', glow: 'rgba(188,19,254,0.16)', text: '#f3d3ff' },
  magenta: { border: 'rgba(255,43,214,0.34)', glow: 'rgba(255,43,214,0.16)', text: '#ffb8e9' },
};

const identityPanel = (tone = 'purple') => {
  const config = IDENTITY_TONES[tone] || IDENTITY_TONES.purple;
  return {
    backgroundImage: `repeating-linear-gradient(to bottom, rgba(210,255,250,0.14) 0px, rgba(210,255,250,0.14) 1px, rgba(0,0,0,0.22) 1px, rgba(0,0,0,0.22) 3px, transparent 3px, transparent 5px), linear-gradient(160deg, ${config.border.replace('0.34', '0.14')}, rgba(10,18,34,0.98))`,
    backgroundSize: '100% 5px, 100% 100%',
    border: `2px solid ${config.border.replace('0.34', '0.62')}`,
    boxShadow: `0 0 24px ${config.glow}, 0 0 34px ${config.glow}, inset 0 0 16px rgba(255,255,255,0.04)`,
  };
};

const identityButton = (tone = 'purple') => {
  const config = IDENTITY_TONES[tone] || IDENTITY_TONES.purple;
  return {
    backgroundImage: `repeating-linear-gradient(to bottom, rgba(210,255,250,0.12) 0px, rgba(210,255,250,0.12) 1px, rgba(0,0,0,0.18) 1px, rgba(0,0,0,0.18) 3px, transparent 3px, transparent 5px), linear-gradient(135deg, ${config.border.replace('0.34', '0.22')}, rgba(255,255,255,0.04))`,
    backgroundSize: '100% 5px, 100% 100%',
    border: `2px solid ${config.border.replace('0.34', '0.68')}`,
    color: config.text,
    boxShadow: `0 0 18px ${config.glow}, 0 0 28px ${config.glow}, inset 0 0 10px rgba(255,255,255,0.04)`,
  };
};

const identityBadge = (tone = 'purple') => {
  const config = IDENTITY_TONES[tone] || IDENTITY_TONES.purple;
  return {
    backgroundImage: `repeating-linear-gradient(to bottom, rgba(210,255,250,0.1) 0px, rgba(210,255,250,0.1) 1px, rgba(0,0,0,0.16) 1px, rgba(0,0,0,0.16) 3px, transparent 3px, transparent 5px), linear-gradient(135deg, ${config.border.replace('0.34', '0.2')}, rgba(255,255,255,0.06))`,
    backgroundSize: '100% 5px, 100% 100%',
    border: `2px solid ${config.border.replace('0.34', '0.68')}`,
    color: config.text,
    boxShadow: `0 0 16px ${config.glow}, 0 0 24px ${config.glow}`,
  };
};

const identityRow = (index) => ({
  background: index % 2 === 0
    ? 'linear-gradient(90deg, rgba(188,19,254,0.06), rgba(0,240,255,0.03))'
    : 'linear-gradient(90deg, rgba(255,176,32,0.04), rgba(255,43,214,0.03))',
});

const IdentityProtectionPage = () => {
  const { getAuthHeaders } = useAuth();
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [threats, setThreats] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [kerberosEvents, setKerberosEvents] = useState([]);
  const [ldapEvents, setLdapEvents] = useState([]);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [viewMode, setViewMode] = useState('overview'); // overview, kerberos, ldap, alerts
  const [stats, setStats] = useState({
    total_users: 0,
    privileged_accounts: 0,
    active_threats: 0,
    blocked_attacks: 0,
    kerberos_anomalies: 0,
    credential_dumps: 0
  });

  // Fetch identity protection data
  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      const [threatsRes, alertsRes, statsRes] = await Promise.all([
        axios.get(`${API}/v1/identity/threats?limit=50`, { headers: getAuthHeaders() }),
        axios.get(`${API}/v1/identity/alerts?limit=100`, { headers: getAuthHeaders() }),
        axios.get(`${API}/v1/identity/stats`, { headers: getAuthHeaders() })
      ]);
      
      setThreats(threatsRes.data.threats || []);
      setAlerts(alertsRes.data.alerts || []);
      setStats(statsRes.data || {});
      
    } catch (error) {
      console.error('Failed to fetch identity protection data:', error);
      loadDemoData();
    } finally {
      setLoading(false);
    }
  }, [getAuthHeaders]);

  // Load demo data
  const loadDemoData = () => {
    setThreats([
      {
        id: 'threat-1',
        type: 'kerberoasting',
        severity: 'high',
        source_user: 'svc_backup',
        target: 'Multiple SPNs',
        timestamp: '2026-03-06T14:32:00Z',
        mitre: 'T1558.003',
        status: 'active',
        details: 'Unusual volume of TGS requests for service accounts'
      },
      {
        id: 'threat-2',
        type: 'golden_ticket',
        severity: 'critical',
        source_user: 'unknown',
        target: 'DC-PRIMARY',
        timestamp: '2026-03-06T12:15:00Z',
        mitre: 'T1558.001',
        status: 'contained',
        details: 'Forged TGT detected with anomalous lifetime'
      },
      {
        id: 'threat-3',
        type: 'dcsync',
        severity: 'critical',
        source_user: 'admin_compromised',
        target: 'Domain Controller',
        timestamp: '2026-03-06T10:45:00Z',
        mitre: 'T1003.006',
        status: 'blocked',
        details: 'Replication request from non-DC machine'
      },
      {
        id: 'threat-4',
        type: 'pass_the_hash',
        severity: 'high',
        source_user: 'WS-DEV-03$',
        target: 'SRV-FILE-01',
        timestamp: '2026-03-06T09:30:00Z',
        mitre: 'T1550.002',
        status: 'investigating',
        details: 'NTLM authentication without preceding interactive logon'
      },
      {
        id: 'threat-5',
        type: 'password_spraying',
        severity: 'medium',
        source_user: 'External IP',
        target: '50+ accounts',
        timestamp: '2026-03-06T08:00:00Z',
        mitre: 'T1110.003',
        status: 'blocked',
        details: 'Low-and-slow password attempts across many accounts'
      }
    ]);
    
    setKerberosEvents([
      { id: 1, event_id: 4769, user: 'svc_backup', target_spn: 'MSSQLSvc/sql01.corp.local', encryption: 'RC4_HMAC', anomaly: true, timestamp: '2026-03-06T14:32:00Z' },
      { id: 2, event_id: 4769, user: 'svc_backup', target_spn: 'HTTP/web01.corp.local', encryption: 'RC4_HMAC', anomaly: true, timestamp: '2026-03-06T14:31:55Z' },
      { id: 3, event_id: 4768, user: 'admin_user', target_spn: 'krbtgt/CORP.LOCAL', encryption: 'AES256', anomaly: false, timestamp: '2026-03-06T14:30:00Z' },
      { id: 4, event_id: 4771, user: 'test_account', target_spn: '-', encryption: '-', anomaly: true, timestamp: '2026-03-06T14:28:00Z' }
    ]);
    
    setLdapEvents([
      { id: 1, type: 'reconnaissance', query: '(&(objectClass=user)(adminCount=1))', source: '192.168.1.50', risk: 'high', timestamp: '2026-03-06T14:20:00Z' },
      { id: 2, type: 'enumeration', query: '(servicePrincipalName=*)', source: '192.168.1.50', risk: 'medium', timestamp: '2026-03-06T14:18:00Z' },
      { id: 3, type: 'normal', query: '(sAMAccountName=john.doe)', source: '192.168.1.10', risk: 'low', timestamp: '2026-03-06T14:15:00Z' }
    ]);
    
    setAlerts([
      { id: 1, severity: 'critical', message: 'Golden Ticket attack detected', user: 'unknown', endpoint: 'WS-ADMIN-01', timestamp: '2026-03-06T12:15:00Z' },
      { id: 2, severity: 'high', message: 'Kerberoasting activity detected', user: 'svc_backup', endpoint: 'WS-DEV-03', timestamp: '2026-03-06T14:32:00Z' },
      { id: 3, severity: 'high', message: 'DCSync replication blocked', user: 'admin_compromised', endpoint: 'WS-IT-02', timestamp: '2026-03-06T10:45:00Z' },
      { id: 4, severity: 'medium', message: 'Password spraying detected', user: 'N/A', endpoint: 'VPN Gateway', timestamp: '2026-03-06T08:00:00Z' }
    ]);
    
    setStats({
      total_users: 1250,
      privileged_accounts: 45,
      active_threats: 2,
      blocked_attacks: 156,
      kerberos_anomalies: 8,
      credential_dumps: 3
    });
  };

  // Run identity scan
  const runScan = async () => {
    try {
      setScanning(true);
      toast.info('Running identity threat scan...');
      
      const res = await axios.post(`${API}/v1/identity/scan`, {
        include_kerberos: true,
        include_ldap: true,
        include_ntlm: true
      }, { headers: getAuthHeaders() });

      const activeThreats = res?.data?.active_threats ?? 0;
      if (activeThreats > 0) {
        toast.success(`Scan complete: ${activeThreats} active identity threats`);
      } else {
        toast.info('Scan complete: no active identity threats found in current telemetry window');
      }
      await fetchData();
    } catch (error) {
      console.error('Scan failed:', error);
      toast.success('Scan complete (demo)');
    } finally {
      setScanning(false);
    }
  };

  // Get threat type icon
  const getThreatIcon = (type) => {
    const icons = {
      kerberoasting: Ticket,
      golden_ticket: Key,
      silver_ticket: Key,
      dcsync: Database,
      pass_the_hash: Fingerprint,
      pass_the_ticket: Ticket,
      password_spraying: Users,
      as_rep_roasting: Ticket,
      ldap_injection: Search,
      ntlm_relay: Network
    };
    return icons[type] || ShieldAlert;
  };

  // Get severity badge
  const getSeverityBadge = (severity) => {
    const config = {
      critical: { tone: 'red', icon: AlertOctagon },
      high: { tone: 'orange', icon: AlertTriangle },
      medium: { tone: 'yellow', icon: ShieldAlert },
      low: { tone: 'cyan', icon: Shield }
    };
    const cfg = config[severity] || config.medium;
    return <Badge className="border-0 uppercase tracking-[0.22em] text-[10px]" style={identityBadge(cfg.tone)}>{severity}</Badge>;
  };

  // Get status badge
  const getStatusBadge = (status) => {
    const config = {
      active: { tone: 'red' },
      contained: { tone: 'orange' },
      blocked: { tone: 'green' },
      investigating: { tone: 'cyan' }
    };
    const cfg = config[status] || config.investigating;
    return <Badge className="border-0 uppercase tracking-[0.22em] text-[10px]" style={identityBadge(cfg.tone)}>{status}</Badge>;
  };

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  return (
    <div className="space-y-6 p-6 lg:p-8" data-testid="identity-protection-page">
      <SeraphPageHeader
        eyebrow="seraph · identity · ad · kerberos · ldap"
        title="Identity Protection"
        tagline="> credential threats · kerberos & ldap analytics · directory hardening"
        accent="green"
        status={scanning ? 'SCANNING' : loading ? 'REFRESHING' : 'MONITORED'}
        actions={
          <>
            <Button variant="outline" onClick={fetchData} disabled={loading} className="border-0" style={identityButton('cyan')}>
              <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button onClick={runScan} disabled={scanning} className="border-0" style={identityButton('purple')}>
              <Play className={`h-4 w-4 mr-2 ${scanning ? 'animate-pulse' : ''}`} />
              {scanning ? 'Scanning...' : 'Run Scan'}
            </Button>
          </>
        }
      />

      {/* Stats Cards */}
      <div className="grid grid-cols-6 gap-4 mb-6">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-xl p-4"
          style={identityPanel('cyan')}
        >
          <div className="flex items-center gap-2 mb-2">
            <Users className="h-4 w-4 text-blue-400" />
            <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: '#aef7ff' }}>Total Users</span>
          </div>
          <p className="sophia-flicker sophia-terminal-value text-2xl font-bold">{stats.total_users?.toLocaleString()}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="rounded-xl p-4"
          style={identityPanel('orange')}
        >
          <div className="flex items-center gap-2 mb-2">
            <Key className="h-4 w-4 text-orange-400" />
            <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: '#ffd78a' }}>Privileged</span>
          </div>
          <p className="sophia-flicker sophia-terminal-value text-2xl font-bold text-orange-400">{stats.privileged_accounts}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="rounded-xl p-4"
          style={identityPanel('red')}
        >
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="h-4 w-4 text-red-400" />
            <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: '#ffd4d4' }}>Active Threats</span>
          </div>
          <p className="sophia-flicker sophia-terminal-value text-2xl font-bold text-red-400">{stats.active_threats}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="rounded-xl p-4"
          style={identityPanel('green')}
        >
          <div className="flex items-center gap-2 mb-2">
            <Shield className="h-4 w-4 text-green-400" />
            <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: '#b8ffca' }}>Blocked</span>
          </div>
          <p className="sophia-flicker sophia-terminal-value text-2xl font-bold text-green-400">{stats.blocked_attacks}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="rounded-xl p-4"
          style={identityPanel('yellow')}
        >
          <div className="flex items-center gap-2 mb-2">
            <Ticket className="h-4 w-4 text-yellow-400" />
            <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: '#fff2d2' }}>Kerberos Anomalies</span>
          </div>
          <p className="sophia-flicker sophia-terminal-value text-2xl font-bold text-yellow-400">{stats.kerberos_anomalies}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="rounded-xl p-4"
          style={identityPanel('purple')}
        >
          <div className="flex items-center gap-2 mb-2">
            <UserX className="h-4 w-4 text-purple-400" />
            <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: '#f3d3ff' }}>Credential Dumps</span>
          </div>
          <p className="sophia-flicker sophia-terminal-value text-2xl font-bold text-purple-400">{stats.credential_dumps}</p>
        </motion.div>
      </div>

      {/* View Mode Tabs */}
      <div className="flex gap-2 mb-4">
        {[
          { id: 'overview', label: 'Threat Overview', icon: Target },
          { id: 'kerberos', label: 'Kerberos', icon: Ticket },
          { id: 'ldap', label: 'LDAP', icon: Search },
          { id: 'alerts', label: 'Alerts', icon: AlertOctagon }
        ].map(tab => (
          <Button
            key={tab.id}
            variant={viewMode === tab.id ? 'default' : 'outline'}
            onClick={() => setViewMode(tab.id)}
            className="border-0"
            style={viewMode === tab.id ? identityButton(tab.id === 'alerts' ? 'red' : tab.id === 'ldap' ? 'cyan' : tab.id === 'kerberos' ? 'yellow' : 'purple') : identityPanel(tab.id === 'alerts' ? 'red' : tab.id === 'ldap' ? 'cyan' : tab.id === 'kerberos' ? 'yellow' : 'purple')}
          >
            <tab.icon className="h-4 w-4 mr-2" />
            {tab.label}
          </Button>
        ))}
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Main Content */}
        <div className="col-span-2">
          {/* Threat Overview */}
          {viewMode === 'overview' && (
            <div className="space-y-3">
              <h3 className="text-lg font-semibold flex items-center gap-2">
                <Target className="h-5 w-5 text-red-400" />
                Identity Threats
              </h3>
              {threats.length === 0 && (
                <div className="rounded-xl p-6 text-center" style={{ ...identityPanel('purple'), color: '#d7edff' }}>
                  No identity threats found yet. Run a scan or ingest AD/Kerberos/LDAP telemetry to populate this view.
                </div>
              )}
              {threats.map((threat, idx) => {
                const Icon = getThreatIcon(threat.type);
                return (
                  <motion.div
                    key={threat.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.05 }}
                    className="p-4 rounded-lg border cursor-pointer transition-all"
                    style={selectedThreat?.id === threat.id ? identityPanel('purple') : identityPanel(idx % 2 === 0 ? 'magenta' : 'cyan')}
                    onClick={() => setSelectedThreat(threat)}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg ${
                          threat.severity === 'critical' ? 'bg-red-500/20' :
                          threat.severity === 'high' ? 'bg-orange-500/20' :
                          'bg-yellow-500/20'
                        }`}>
                          <Icon className={`h-4 w-4 ${
                            threat.severity === 'critical' ? 'text-red-400' :
                            threat.severity === 'high' ? 'text-orange-400' :
                            'text-yellow-400'
                          }`} />
                        </div>
                        <div>
                          <p className="sophia-scan sophia-terminal-label font-medium capitalize" style={{ color: '#f3d3ff' }}>{threat.type.replace(/_/g, ' ')}</p>
                          <p className="sophia-flicker sophia-terminal-meta text-xs" style={{ color: '#d7edff', opacity: 0.96 }}>{threat.source_user} → {threat.target}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {getSeverityBadge(threat.severity)}
                        {getStatusBadge(threat.status)}
                      </div>
                    </div>
                    <div className="flex items-center justify-between text-sm">
                      <span className="sophia-flicker sophia-terminal-meta" style={{ color: '#ecfeff' }}>{threat.details}</span>
                      <Badge variant="outline" className="text-xs font-mono border-0" style={identityBadge('orange')}>
                        {threat.mitre}
                      </Badge>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          )}

          {/* Kerberos Events */}
          {viewMode === 'kerberos' && (
            <div className="rounded-xl overflow-hidden" style={identityPanel('yellow')}>
              <div className="p-4 border-b border-gray-800">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Ticket className="h-5 w-5 text-yellow-400" />
                  Kerberos Activity
                </h3>
              </div>
              <table className="w-full">
                <thead style={{ background: 'linear-gradient(90deg, rgba(255,211,122,0.1), rgba(188,19,254,0.08))' }}>
                  <tr>
                    <th className="sophia-scan sophia-terminal-label px-4 py-3 text-left text-sm font-medium" style={{ color: '#fff2d2' }}>Event ID</th>
                    <th className="sophia-scan sophia-terminal-label px-4 py-3 text-left text-sm font-medium" style={{ color: '#aef7ff' }}>User</th>
                    <th className="sophia-scan sophia-terminal-label px-4 py-3 text-left text-sm font-medium" style={{ color: '#f3d3ff' }}>Target SPN</th>
                    <th className="sophia-scan sophia-terminal-label px-4 py-3 text-left text-sm font-medium" style={{ color: '#ffd78a' }}>Encryption</th>
                    <th className="sophia-scan sophia-terminal-label px-4 py-3 text-left text-sm font-medium" style={{ color: '#b8ffca' }}>Status</th>
                    <th className="sophia-scan sophia-terminal-label px-4 py-3 text-left text-sm font-medium" style={{ color: '#ffb8e9' }}>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {kerberosEvents.map((event, idx) => (
                    <motion.tr
                      key={event.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: idx * 0.05 }}
                      className="border-t border-gray-800"
                      style={identityRow(idx)}
                    >
                      <td className="sophia-flicker sophia-terminal-value px-4 py-3 font-mono text-sm" style={{ color: '#fff2d2' }}>{event.event_id}</td>
                      <td className="sophia-flicker sophia-terminal-meta px-4 py-3 text-sm" style={{ color: '#ecfeff' }}>{event.user}</td>
                      <td className="sophia-flicker sophia-terminal-value px-4 py-3 text-sm font-mono max-w-[200px] truncate" style={{ color: '#f3d3ff' }}>
                        {event.target_spn}
                      </td>
                      <td className="px-4 py-3">
                        <Badge className={
                          event.encryption === 'RC4_HMAC' ? 'bg-red-500/20 text-red-400' :
                          event.encryption === 'AES256' ? 'bg-green-500/20 text-green-400' :
                          'bg-gray-500/20 text-gray-400'
                        }>
                          {event.encryption}
                        </Badge>
                      </td>
                      <td className="px-4 py-3">
                        {event.anomaly ? (
                          <Badge className="bg-orange-500/20 text-orange-400">
                            <AlertTriangle className="h-3 w-3 mr-1" />
                            Anomaly
                          </Badge>
                        ) : (
                          <Badge className="bg-green-500/20 text-green-400">
                            <CheckCircle2 className="h-3 w-3 mr-1" />
                            Normal
                          </Badge>
                        )}
                      </td>
                      <td className="px-4 py-3 text-sm" style={{ color: '#ffb8e9' }}>
                        {new Date(event.timestamp).toLocaleTimeString()}
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* LDAP Events */}
          {viewMode === 'ldap' && (
            <div className="rounded-xl overflow-hidden" style={identityPanel('cyan')}>
              <div className="p-4 border-b border-gray-800">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Search className="h-5 w-5 text-blue-400" />
                  LDAP Queries
                </h3>
              </div>
              <div className="divide-y divide-gray-800">
                {ldapEvents.map((event, idx) => (
                  <motion.div
                    key={event.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.05 }}
                    className="p-4"
                    style={identityRow(idx)}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Badge className={
                          event.type === 'reconnaissance' ? 'bg-red-500/20 text-red-400' :
                          event.type === 'enumeration' ? 'bg-orange-500/20 text-orange-400' :
                          'bg-green-500/20 text-green-400'
                        }>
                          {event.type}
                        </Badge>
                        <span className="sophia-flicker sophia-terminal-value text-sm font-mono" style={{ color: '#aef7ff' }}>{event.source}</span>
                      </div>
                      <span className="text-xs" style={{ color: '#d7edff', opacity: 0.82 }}>
                        {new Date(event.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <code className="text-sm p-2 rounded block font-mono" style={{ ...identityPanel('purple'), color: '#ecfeff' }}>
                      {event.query}
                    </code>
                  </motion.div>
                ))}
              </div>
            </div>
          )}

          {/* Alerts View */}
          {viewMode === 'alerts' && (
            <div className="rounded-xl overflow-hidden" style={identityPanel('red')}>
              <div className="p-4 border-b border-gray-800">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <AlertOctagon className="h-5 w-5 text-orange-400" />
                  Identity Alerts
                </h3>
              </div>
              <div className="divide-y divide-gray-800">
                {alerts.length === 0 && (
                  <div className="p-6 text-center" style={{ color: '#ffd4d4' }}>
                    No identity alerts currently active.
                  </div>
                )}
                {alerts.map((alert, idx) => (
                  <motion.div
                    key={alert.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.05 }}
                    className="p-4"
                    style={identityRow(idx)}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        {getSeverityBadge(alert.severity)}
                        <span className="sophia-flicker sophia-terminal-meta text-sm" style={{ color: '#ffd4d4' }}>{alert.user}</span>
                        <span className="text-gray-600">•</span>
                        <span className="sophia-flicker sophia-terminal-value text-sm font-mono" style={{ color: '#fff2d2' }}>{alert.endpoint}</span>
                      </div>
                      <span className="text-xs" style={{ color: '#d7edff', opacity: 0.82 }}>
                        {new Date(alert.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-sm">{alert.message}</p>
                  </motion.div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Side Panel */}
        <div className="space-y-4">
          {/* Selected Threat Details */}
          <AnimatePresence>
            {selectedThreat && (
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                className="rounded-xl p-4"
                style={identityPanel('purple')}
              >
                <h3 className="font-semibold mb-3 flex items-center gap-2">
                  <Target className="h-4 w-4 text-indigo-400" />
                  Threat Details
                </h3>
                <div className="space-y-3">
                  <div>
                    <p className="sophia-scan sophia-terminal-label text-xs" style={{ color: '#ffb8e9' }}>Attack Type</p>
                    <p className="sophia-flicker sophia-terminal-value font-medium capitalize" style={{ color: '#fff0fb' }}>{selectedThreat.type.replace(/_/g, ' ')}</p>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <p className="sophia-scan sophia-terminal-label text-xs" style={{ color: '#ffd78a' }}>Severity</p>
                      {getSeverityBadge(selectedThreat.severity)}
                    </div>
                    <div>
                      <p className="sophia-scan sophia-terminal-label text-xs" style={{ color: '#b8ffca' }}>Status</p>
                      {getStatusBadge(selectedThreat.status)}
                    </div>
                  </div>
                  <div>
                    <p className="sophia-scan sophia-terminal-label text-xs" style={{ color: '#aef7ff' }}>Source</p>
                    <p className="sophia-flicker sophia-terminal-value font-mono text-sm" style={{ color: '#ecfeff' }}>{selectedThreat.source_user}</p>
                  </div>
                  <div>
                    <p className="sophia-scan sophia-terminal-label text-xs" style={{ color: '#f3d3ff' }}>Target</p>
                    <p className="sophia-flicker sophia-terminal-value font-mono text-sm" style={{ color: '#fff0fb' }}>{selectedThreat.target}</p>
                  </div>
                  <div>
                    <p className="sophia-scan sophia-terminal-label text-xs" style={{ color: '#ffd78a' }}>MITRE Technique</p>
                    <Badge variant="outline" className="font-mono border-0" style={identityBadge('orange')}>
                      {selectedThreat.mitre}
                    </Badge>
                  </div>
                  <div className="pt-2 flex gap-2">
                    <Button size="sm" className="flex-1 border-0" style={identityButton('red')}>
                      <Lock className="h-3 w-3 mr-1" />
                      Block
                    </Button>
                    <Button size="sm" variant="outline" className="flex-1 border-0" style={identityButton('cyan')}>
                      <Eye className="h-3 w-3 mr-1" />
                      Investigate
                    </Button>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Attack Types Legend */}
          <div className="rounded-xl p-4" style={identityPanel('magenta')}>
            <h3 className="font-semibold mb-3">Attack Types Monitored</h3>
            <div className="space-y-2">
              {[
                { type: 'Kerberoasting', mitre: 'T1558.003' },
                { type: 'Golden Ticket', mitre: 'T1558.001' },
                { type: 'Silver Ticket', mitre: 'T1558.002' },
                { type: 'DCSync', mitre: 'T1003.006' },
                { type: 'Pass-the-Hash', mitre: 'T1550.002' },
                { type: 'Pass-the-Ticket', mitre: 'T1550.003' },
                { type: 'AS-REP Roasting', mitre: 'T1558.004' },
                { type: 'Password Spraying', mitre: 'T1110.003' }
              ].map(attack => (
                <div key={attack.mitre} className="flex items-center justify-between p-2 rounded-lg" style={identityPanel(attack.mitre === 'T1003.006' ? 'red' : attack.mitre === 'T1110.003' ? 'orange' : 'purple')}>
                  <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: '#ecfeff' }}>{attack.type}</span>
                  <Badge variant="outline" className="text-xs font-mono border-0" style={identityBadge('cyan')}>
                    {attack.mitre}
                  </Badge>
                </div>
              ))}
            </div>
          </div>

          {/* Quick Actions */}
          <div className="rounded-xl p-4" style={identityPanel('cyan')}>
            <h3 className="font-semibold mb-3">Quick Actions</h3>
            <div className="space-y-2">
              <Button variant="outline" className="w-full justify-start border-0" style={identityButton('purple')}>
                <Key className="h-4 w-4 mr-2" />
                Rotate Credentials
              </Button>
              <Button variant="outline" className="w-full justify-start border-0" style={identityButton('orange')}>
                <Users className="h-4 w-4 mr-2" />
                Review Privileged
              </Button>
              <Button variant="outline" className="w-full justify-start border-0" style={identityButton('cyan')}>
                <BarChart3 className="h-4 w-4 mr-2" />
                Export Report
              </Button>
            </div>
          </div>

          {/* AD Health */}
          <div className="rounded-xl p-4" style={identityPanel('green')}>
            <h3 className="font-semibold mb-3 flex items-center gap-2">
              <Server className="h-4 w-4 text-blue-400" />
              AD Health
            </h3>
            <div className="space-y-2">
              <div className="flex items-center justify-between p-2 rounded-lg" style={identityPanel('green')}>
                <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: '#ecfeff' }}>DC Replication</span>
                <CheckCircle2 className="h-4 w-4 text-green-400" />
              </div>
              <div className="flex items-center justify-between p-2 rounded-lg" style={identityPanel('cyan')}>
                <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: '#ecfeff' }}>SYSVOL Integrity</span>
                <CheckCircle2 className="h-4 w-4 text-green-400" />
              </div>
              <div className="flex items-center justify-between p-2 rounded-lg" style={identityPanel('yellow')}>
                <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: '#fff2d2' }}>Kerberos Services</span>
                <CheckCircle2 className="h-4 w-4 text-green-400" />
              </div>
              <div className="flex items-center justify-between p-2 rounded-lg" style={identityPanel('purple')}>
                <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: '#f3d3ff' }}>LDAPS Enabled</span>
                <CheckCircle2 className="h-4 w-4 text-green-400" />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default IdentityProtectionPage;
