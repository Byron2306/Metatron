import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion, AnimatePresence } from 'framer-motion';
import SeraphPageHeader from '../components/SeraphPageHeader';
import { 
  Shield, 
  RefreshCw, 
  AlertTriangle, 
  Activity,
  HardDrive,
  Lock,
  Unlock,
  CheckCircle2,
  XCircle,
  Cpu,
  Server,
  Fingerprint,
  Key,
  FileCode,
  Layers,
  AlertOctagon,
  Clock,
  TrendingUp,
  Zap,
  Eye,
  ChevronRight,
  Play,
  BarChart3,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Link2,
  Unlink2
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const SECURE_BOOT_TONES = {
  cyan: { border: 'rgba(0,240,255,0.34)', glow: 'rgba(0,240,255,0.16)', text: '#aef7ff' },
  green: { border: 'rgba(57,255,20,0.34)', glow: 'rgba(57,255,20,0.16)', text: '#b8ffca' },
  orange: { border: 'rgba(255,176,32,0.34)', glow: 'rgba(255,176,32,0.16)', text: '#ffd78a' },
  magenta: { border: 'rgba(255,43,214,0.34)', glow: 'rgba(255,43,214,0.16)', text: '#ffb8e9' },
  red: { border: 'rgba(255,91,91,0.34)', glow: 'rgba(255,91,91,0.14)', text: '#ffd4d4' },
};

const secureBootPanel = (tone = 'cyan') => {
  const config = SECURE_BOOT_TONES[tone] || SECURE_BOOT_TONES.cyan;
  return {
    backgroundImage: `linear-gradient(160deg, ${config.border.replace('0.34', '0.16')}, rgba(10,18,34,0.96))`,
    border: `2px solid ${config.border.replace('0.34', '0.62')}`,
    boxShadow: `0 0 8px ${config.glow}, 0 0 18px ${config.glow}, inset 0 0 14px ${config.glow}`,
  };
};

const secureBootButton = (tone = 'cyan') => {
  const config = SECURE_BOOT_TONES[tone] || SECURE_BOOT_TONES.cyan;
  return {
    backgroundImage: `linear-gradient(135deg, ${config.border.replace('0.34', '0.24')}, ${config.border.replace('0.34', '0.1')})`,
    border: `2px solid ${config.border.replace('0.34', '0.68')}`,
    color: config.text,
    boxShadow: `0 0 8px ${config.glow}, inset 0 0 11px ${config.glow}`,
  };
};

const secureBootBadge = (tone = 'cyan') => {
  const config = SECURE_BOOT_TONES[tone] || SECURE_BOOT_TONES.cyan;
  return {
    backgroundImage: `linear-gradient(135deg, ${config.border.replace('0.34', '0.22')}, ${config.border.replace('0.34', '0.1')})`,
    border: `2px solid ${config.border.replace('0.34', '0.68')}`,
    color: config.text,
    boxShadow: `0 0 8px ${config.glow}, inset 0 0 10px ${config.glow}`,
  };
};

const secureBootRow = (index) => ({
  background: index % 2 === 0
    ? 'linear-gradient(90deg, rgba(0,240,255,0.06), rgba(255,43,214,0.03))'
    : 'linear-gradient(90deg, rgba(255,176,32,0.04), rgba(57,255,20,0.03))',
});

const SecureBootPage = () => {
  const { getAuthHeaders } = useAuth();
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [status, setStatus] = useState(null);
  const [bootChain, setBootChain] = useState(null);
  const [firmware, setFirmware] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [scanResult, setScanResult] = useState(null);
  const [selectedComponent, setSelectedComponent] = useState(null);
  const [viewMode, setViewMode] = useState('status'); // status, chain, firmware, alerts
  const [demoMode, setDemoMode] = useState(false);
  const [fleetStats, setFleetStats] = useState({
    total_endpoints: 0,
    secure_boot_enabled: 0,
    tpm_present: 0,
    threats_detected: 0,
    pending_updates: 0
  });

  // Fetch secure boot data
  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      setDemoMode(false);
      const results = await Promise.allSettled([
        axios.get(`${API}/v1/secure-boot/status`, { headers: getAuthHeaders() }),
        axios.get(`${API}/v1/secure-boot/bootchain`, { headers: getAuthHeaders() }),
        axios.get(`${API}/v1/secure-boot/alerts?limit=50`, { headers: getAuthHeaders() }),
        axios.get(`${API}/v1/secure-boot/firmware`, { headers: getAuthHeaders() }),
      ]);

      const [statusRes, chainRes, alertsRes, firmwareRes] = results.map((r) =>
        r.status === 'fulfilled' ? r.value : null
      );

      if (statusRes?.data) setStatus(statusRes.data);
      if (chainRes?.data) setBootChain(chainRes.data);
      if (alertsRes?.data) setAlerts(alertsRes.data.alerts || []);

      if (firmwareRes?.data?.components?.length > 0) {
        setFirmware(
          firmwareRes.data.components.map((c) => ({
            id: c.component_id,
            name: c.name,
            vendor: c.vendor,
            version: c.version,
            secure: c.signature_valid,
            update_available: c.update_available,
          }))
        );
      } else if (firmwareRes?.data?.components) {
        setFirmware([]);
      }

      // Populate the top "fleet" tiles even in single-host mode.
      if (statusRes?.data) {
        const components = firmwareRes?.data?.components || [];
        const pendingUpdates = Array.isArray(components)
          ? components.filter((c) => c?.update_available).length
          : 0;
        const threatCount = Array.isArray(alertsRes?.data?.alerts) ? alertsRes.data.alerts.length : 0;
        setFleetStats({
          total_endpoints: 1,
          secure_boot_enabled: statusRes.data.secure_boot_enabled ? 1 : 0,
          tpm_present: statusRes.data.tpm_present ? 1 : 0,
          threats_detected: threatCount,
          pending_updates: pendingUpdates,
        });
      }

      // Only fall back to demo if the core endpoints are unavailable.
      if (!statusRes || !chainRes) {
        setDemoMode(true);
        toast.warning('Secure Boot telemetry is partially unavailable — some panels may show placeholders');
      }
      
    } catch (error) {
      console.error('Failed to fetch secure boot data:', error);
      setDemoMode(true);
      toast.warning('Secure Boot API unavailable — showing demo data');
      loadDemoData();
    } finally {
      setLoading(false);
    }
  }, [getAuthHeaders]);

  // Load demo data
  const loadDemoData = () => {
    setStatus({
      platform: 'x86_64',
      uefi_mode: true,
      secure_boot_enabled: true,
      secure_boot_enforced: true,
      setup_mode: false,
      pk_enrolled: true,
      kek_enrolled: true,
      db_enrolled: true,
      dbx_enrolled: true,
      measured_boot_supported: true,
      tpm_present: true,
      tpm_version: '2.0',
      virtualization_based_security: true,
      last_check: new Date().toISOString(),
      risk_level: 'low'
    });
    
    setBootChain({
      verified: true,
      chain_intact: true,
      components: [
        { name: 'UEFI Firmware', verified: true, hash: 'a1b2c3d4...', signer: 'Dell Inc.' },
        { name: 'Boot Manager', verified: true, hash: 'e5f6g7h8...', signer: 'Microsoft' },
        { name: 'OS Loader', verified: true, hash: 'i9j0k1l2...', signer: 'Microsoft' },
        { name: 'Kernel', verified: true, hash: 'm3n4o5p6...', signer: 'Microsoft' },
        { name: 'Early Launch Drivers', verified: true, hash: 'q7r8s9t0...', signer: 'Various' }
      ],
      chain_of_trust: [
        { from: 'UEFI Platform Key (PK)', to: 'Key Exchange Key (KEK)', status: 'valid' },
        { from: 'KEK', to: 'Signature Database (db)', status: 'valid' },
        { from: 'db', to: 'Boot Manager', status: 'valid' },
        { from: 'Boot Manager', to: 'OS Loader', status: 'valid' }
      ],
      issues: [],
      mitre_techniques: []
    });
    
    setFirmware([]);
    
    setAlerts([]);
    
    setFleetStats({
      total_endpoints: 156,
      secure_boot_enabled: 148,
      tpm_present: 152,
      threats_detected: 2,
      pending_updates: 12
    });
  };

  // Run firmware scan
  const runScan = async () => {
    try {
      setScanning(true);
      toast.info('Running firmware security scan...');
      
      const res = await axios.post(`${API}/v1/secure-boot/scan`, {
        deep_scan: true,
        check_updates: true,
        verify_signatures: true
      }, { headers: getAuthHeaders() });
      
      setScanResult(res.data);
      toast.success('Scan complete');
      await fetchData();
    } catch (error) {
      console.error('Scan failed:', error);
      // Demo scan result
      setScanResult({
        scan_id: 'scan-' + Date.now(),
        status: 'completed',
        started_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
        total_components: 12,
        verified_components: 11,
        suspicious_components: 1,
        threats_detected: [],
        recommendations: [
          'Update Intel ME Firmware to version 16.1.30',
          'Enable Memory Integrity in Windows Security'
        ]
      });
      toast.success('Scan complete (demo)');
    } finally {
      setScanning(false);
    }
  };

  // Get risk level badge
  const getRiskBadge = (level) => {
    const config = {
      low:      { variant: 'success',     icon: ShieldCheck },
      medium:   { variant: 'warning',     icon: ShieldAlert },
      high:     { variant: 'warning',     icon: ShieldAlert },
      critical: { variant: 'destructive', icon: ShieldX },
      unknown:  { variant: 'outline',     icon: AlertTriangle }
    };
    const cfg = config[level] || config.low;
    const Icon = cfg.icon;
    const tone = level === 'critical' ? 'red' : level === 'high' ? 'magenta' : level === 'medium' ? 'orange' : 'green';
    return (
      <Badge variant={cfg.variant} style={secureBootBadge(tone)} className="border-0 uppercase tracking-[0.22em] text-[10px]">
        <Icon className="h-3 w-3 mr-1" />
        {level}
      </Badge>
    );
  };

  // Get component status indicator
  const getStatusIndicator = (verified) => {
    return verified ? (
      <CheckCircle2 className="h-4 w-4 text-green-400" />
    ) : (
      <XCircle className="h-4 w-4 text-red-400" />
    );
  };

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  return (
    <div className="space-y-6 p-6 lg:p-8" data-testid="secure-boot-page">
      <SeraphPageHeader
        eyebrow="seraph · secure boot · firmware trust"
        title="Secure Boot Verification"
        tagline="> uefi · tpm · firmware integrity · measured boot chain"
        accent="gold"
        status={loading ? 'REFRESHING' : scanning ? 'SCANNING' : 'VERIFIED'}
        actions={
          <>
            <Button
              variant="outline"
              onClick={fetchData}
              disabled={loading}
              className="border-0"
              style={secureBootButton('cyan')}
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button
              onClick={runScan}
              disabled={scanning}
              className="border-0"
              style={secureBootButton('magenta')}
            >
              <Play className={`h-4 w-4 mr-2 ${scanning ? 'animate-pulse' : ''}`} />
              {scanning ? 'Scanning...' : 'Run Scan'}
            </Button>
          </>
        }
      />

      {(demoMode || status?.measurement_available === false) && (
        <div
          className="mb-6 p-3 rounded-lg border text-sm flex items-start gap-2"
          style={{
            backgroundColor: demoMode ? 'rgba(245, 158, 11, 0.08)' : 'rgba(56, 189, 248, 0.08)',
            borderColor: demoMode ? 'rgba(245, 158, 11, 0.35)' : 'rgba(56, 189, 248, 0.35)'
          }}
        >
          <AlertTriangle className="w-4 h-4 mt-0.5" style={{ color: demoMode ? '#F59E0B' : '#38BDF8' }} />
          <div className="space-y-1">
            {demoMode && (
              <div className="text-amber-200">
                Demo data is being displayed because the Secure Boot API could not be reached.
              </div>
            )}
            {status?.measurement_available === false && (
              <div className="text-cyan-200">
                Secure Boot measurement is unavailable in this runtime (common in containers).{' '}
                {status?.measurement_note || ''}
                {typeof status?.operator_override_secure_boot_enabled === 'boolean' && (
                  <span className="ml-1">
                    Operator override: <span className="font-mono">{String(status.operator_override_secure_boot_enabled)}</span>.
                  </span>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Fleet Stats */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-xl p-4"
          style={secureBootPanel('cyan')}
        >
          <div className="flex items-center gap-2 mb-2">
            <Server className="h-4 w-4 text-blue-400" />
            <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: '#aef7ff' }}>Total Endpoints</span>
          </div>
          <p className="sophia-flicker sophia-terminal-value text-2xl font-bold">{fleetStats.total_endpoints}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="rounded-xl p-4"
          style={secureBootPanel('green')}
        >
          <div className="flex items-center gap-2 mb-2">
            <Lock className="h-4 w-4 text-green-400" />
            <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: '#b8ffca' }}>Secure Boot Enabled</span>
          </div>
          <p className="sophia-flicker sophia-terminal-value text-2xl font-bold text-green-400">{fleetStats.secure_boot_enabled}</p>
          <p className="sophia-terminal-meta text-xs" style={{ color: '#d7ffd4', opacity: 0.96 }}>
            {fleetStats.total_endpoints > 0
              ? `${Math.round((fleetStats.secure_boot_enabled / fleetStats.total_endpoints) * 100)}% coverage`
              : 'N/A'}
          </p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="rounded-xl p-4"
          style={secureBootPanel('cyan')}
        >
          <div className="flex items-center gap-2 mb-2">
            <Fingerprint className="h-4 w-4 text-cyan-400" />
            <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: '#aef7ff' }}>TPM Present</span>
          </div>
          <p className="sophia-flicker sophia-terminal-value text-2xl font-bold text-cyan-400">{fleetStats.tpm_present}</p>
          <p className="sophia-terminal-meta text-xs" style={{ color: '#d7fbff', opacity: 0.96 }}>
            {fleetStats.total_endpoints > 0
              ? `${Math.round((fleetStats.tpm_present / fleetStats.total_endpoints) * 100)}% equipped`
              : 'N/A'}
          </p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="rounded-xl p-4"
          style={secureBootPanel('red')}
        >
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="h-4 w-4 text-red-400" />
            <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: '#ffd4d4' }}>Threats Detected</span>
          </div>
          <p className="sophia-flicker sophia-terminal-value text-2xl font-bold text-red-400">{fleetStats.threats_detected}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="rounded-xl p-4"
          style={secureBootPanel('orange')}
        >
          <div className="flex items-center gap-2 mb-2">
            <TrendingUp className="h-4 w-4 text-orange-400" />
            <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: '#ffd78a' }}>Pending Updates</span>
          </div>
          <p className="sophia-flicker sophia-terminal-value text-2xl font-bold text-orange-400">{fleetStats.pending_updates}</p>
        </motion.div>
      </div>

      {/* View Mode Tabs */}
      <div className="flex gap-2 mb-4">
        {[
          { id: 'status', label: 'Boot Status', icon: Shield },
          { id: 'chain', label: 'Boot Chain', icon: Link2 },
          { id: 'firmware', label: 'Firmware', icon: Cpu },
          { id: 'alerts', label: 'Alerts', icon: AlertOctagon }
        ].map(tab => (
          <Button
            key={tab.id}
            variant={viewMode === tab.id ? 'default' : 'outline'}
            onClick={() => setViewMode(tab.id)}
            className={`secure-boot-tab secure-boot-tab--${tab.id} border-0`}
            data-tone={tab.id}
            style={viewMode === tab.id ? secureBootButton(tab.id === 'alerts' ? 'magenta' : tab.id === 'firmware' ? 'orange' : tab.id === 'chain' ? 'green' : 'cyan') : secureBootPanel(tab.id === 'alerts' ? 'magenta' : tab.id === 'firmware' ? 'orange' : tab.id === 'chain' ? 'green' : 'cyan')}
          >
            <tab.icon className="h-4 w-4 mr-2" />
            {tab.label}
          </Button>
        ))}
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Main Content */}
        <div className="col-span-2">
          {/* Boot Status View */}
          {viewMode === 'status' && status && (
            <div className="space-y-4">
              <motion.div 
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="rounded-xl p-6"
                style={secureBootPanel('cyan')}
              >
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-lg font-semibold flex items-center gap-2">
                    <ShieldCheck className="h-5 w-5 text-cyan-400" />
                    Secure Boot Status
                  </h3>
                  {getRiskBadge(status.risk_level)}
                </div>
                
                <div className="grid grid-cols-3 gap-6">
                  {/* UEFI Status */}
                  <div className="space-y-3">
                    <h4 className="sophia-scan sophia-terminal-label text-sm font-medium" style={{ color: '#aef7ff' }}>UEFI Configuration</h4>
                    <div className="space-y-2">
                      <div className="sophia-terminal-row sophia-row-glow flex items-center justify-between p-2 rounded-lg" style={secureBootPanel('cyan')}>
                        <span className="sophia-scan sophia-terminal-label text-sm">UEFI Mode</span>
                        {status.measurement_available === false ? (
                          <Badge variant="outline">Unavailable</Badge>
                        ) : (
                          getStatusIndicator(status.uefi_mode)
                        )}
                      </div>
                      <div className="sophia-terminal-row sophia-row-glow flex items-center justify-between p-2 rounded-lg" style={secureBootPanel('cyan')}>
                        <span className="sophia-scan sophia-terminal-label text-sm">Secure Boot</span>
                        {status.measurement_available === false ? (
                          <Badge variant="outline">Unavailable</Badge>
                        ) : (
                          getStatusIndicator(status.secure_boot_enabled)
                        )}
                      </div>
                      <div className="sophia-terminal-row sophia-row-glow flex items-center justify-between p-2 rounded-lg" style={secureBootPanel('green')}>
                        <span className="sophia-scan sophia-terminal-label text-sm">Enforced</span>
                        {getStatusIndicator(status.secure_boot_enforced)}
                      </div>
                      <div className="sophia-terminal-row sophia-row-glow flex items-center justify-between p-2 rounded-lg" style={secureBootPanel('orange')}>
                        <span className="sophia-scan sophia-terminal-label text-sm">Setup Mode</span>
                        {getStatusIndicator(!status.setup_mode)}
                      </div>
                    </div>
                  </div>
                  
                  {/* Key Enrollment */}
                  <div className="space-y-3">
                    <h4 className="sophia-scan sophia-terminal-label text-sm font-medium" style={{ color: '#ffb8e9' }}>Key Enrollment</h4>
                    <div className="space-y-2">
                      <div className="sophia-terminal-row sophia-row-glow flex items-center justify-between p-2 rounded-lg" style={secureBootPanel('magenta')}>
                        <span className="sophia-scan sophia-terminal-label text-sm">Platform Key (PK)</span>
                        {getStatusIndicator(status.pk_enrolled)}
                      </div>
                      <div className="sophia-terminal-row sophia-row-glow flex items-center justify-between p-2 rounded-lg" style={secureBootPanel('magenta')}>
                        <span className="sophia-scan sophia-terminal-label text-sm">Key Exchange (KEK)</span>
                        {getStatusIndicator(status.kek_enrolled)}
                      </div>
                      <div className="sophia-terminal-row sophia-row-glow flex items-center justify-between p-2 rounded-lg" style={secureBootPanel('green')}>
                        <span className="sophia-scan sophia-terminal-label text-sm">Signature DB</span>
                        {getStatusIndicator(status.db_enrolled)}
                      </div>
                      <div className="sophia-terminal-row sophia-row-glow flex items-center justify-between p-2 rounded-lg" style={secureBootPanel('orange')}>
                        <span className="sophia-scan sophia-terminal-label text-sm">Revocation DB (dbx)</span>
                        {getStatusIndicator(status.dbx_enrolled)}
                      </div>
                    </div>
                  </div>
                  
                  {/* TPM & VBS */}
                  <div className="space-y-3">
                    <h4 className="sophia-scan sophia-terminal-label text-sm font-medium" style={{ color: '#ffd78a' }}>Hardware Security</h4>
                    <div className="space-y-2">
                      <div className="sophia-terminal-row sophia-row-glow flex items-center justify-between p-2 rounded-lg" style={secureBootPanel('green')}>
                        <span className="sophia-scan sophia-terminal-label text-sm">TPM Present</span>
                        {getStatusIndicator(status.tpm_present)}
                      </div>
                      <div className="sophia-terminal-row sophia-row-glow flex items-center justify-between p-2 rounded-lg" style={secureBootPanel('cyan')}>
                        <span className="sophia-scan sophia-terminal-label text-sm">TPM Version</span>
                        <span className="sophia-flicker sophia-terminal-value text-sm">{status.tpm_version || 'N/A'}</span>
                      </div>
                      <div className="sophia-terminal-row sophia-row-glow flex items-center justify-between p-2 rounded-lg" style={secureBootPanel('orange')}>
                        <span className="sophia-scan sophia-terminal-label text-sm">Measured Boot</span>
                        {getStatusIndicator(status.measured_boot_supported)}
                      </div>
                      <div className="sophia-terminal-row sophia-row-glow flex items-center justify-between p-2 rounded-lg" style={secureBootPanel('magenta')}>
                        <span className="sophia-scan sophia-terminal-label text-sm">VBS Enabled</span>
                        {getStatusIndicator(status.virtualization_based_security)}
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="mt-4 pt-4 border-t border-gray-800">
                  <p className="text-xs" style={{ color: '#d7fbff', opacity: 0.82 }}>
                    Last verified: {new Date(status.last_check).toLocaleString()} • Platform: {status.platform}
                  </p>
                </div>
              </motion.div>
            </div>
          )}

          {/* Boot Chain View */}
          {viewMode === 'chain' && bootChain && (
            <div className="rounded-xl p-6" style={secureBootPanel('green')}>
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Link2 className="h-5 w-5 text-cyan-400" />
                  Boot Chain Verification
                </h3>
                <Badge variant={bootChain.chain_intact ? 'success' : 'destructive'}>
                  {bootChain.chain_intact ? 'Chain Intact' : 'Chain Broken'}
                </Badge>
              </div>
              
              {/* Chain Components */}
              <div className="space-y-3 mb-6">
                {bootChain.components?.map((comp, idx) => (
                  <motion.div
                    key={idx}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.1 }}
                    className="flex items-center gap-4"
                  >
                    <div className="flex items-center justify-center w-8 h-8 rounded-full text-sm font-mono" style={secureBootPanel('orange')}>
                      {idx + 1}
                    </div>
                    <div className="flex-1 p-3 rounded-lg flex items-center justify-between" style={secureBootPanel(idx % 2 === 0 ? 'cyan' : 'magenta')}>
                      <div>
                        <p className="sophia-scan sophia-terminal-label font-medium" style={{ color: '#ecfeff' }}>{comp.name}</p>
                        <p className="sophia-flicker sophia-terminal-meta text-xs" style={{ color: '#d7fbff', opacity: 0.96 }}>{comp.hash}</p>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="sophia-flicker sophia-terminal-value text-sm" style={{ color: '#ffd78a' }}>{comp.signer}</span>
                        {getStatusIndicator(comp.verified)}
                      </div>
                    </div>
                    {idx < bootChain.components.length - 1 && (
                      <ChevronRight className="h-4 w-4 text-cyan-400" />
                    )}
                  </motion.div>
                ))}
              </div>
              
              {/* Chain of Trust */}
              <div className="border-t border-gray-800 pt-4">
                <h4 className="sophia-scan sophia-terminal-label text-sm font-medium mb-3" style={{ color: '#aef7ff' }}>Chain of Trust</h4>
                <div className="space-y-2">
                  {bootChain.chain_of_trust?.map((link, idx) => (
                    <div key={idx} className="flex items-center gap-3 p-2 rounded-lg" style={secureBootPanel(idx % 2 === 0 ? 'cyan' : 'green')}>
                      <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: '#ecfeff' }}>{link.from}</span>
                      <ChevronRight className="h-4 w-4 text-cyan-400" />
                      <span className="sophia-flicker sophia-terminal-value text-sm" style={{ color: '#b8ffca' }}>{link.to}</span>
                      <Badge variant="success" className="ml-auto text-xs">
                        {link.status}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
              
              {bootChain.issues?.length > 0 && (
                <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                  <h4 className="text-sm font-medium text-red-400 mb-2">Issues Detected</h4>
                  <ul className="list-disc list-inside text-sm" style={{ color: '#ffd4d4' }}>
                    {bootChain.issues.map((issue, idx) => (
                      <li key={idx}>{issue}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Firmware View */}
          {viewMode === 'firmware' && (
            <div className="rounded-xl overflow-hidden" style={secureBootPanel('orange')}>
              <div className="p-4 border-b border-gray-800">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Cpu className="h-5 w-5 text-cyan-400" />
                  Firmware Inventory
                </h3>
              </div>
              <table className="w-full">
                <thead style={{ background: 'linear-gradient(90deg, rgba(255,176,32,0.1), rgba(255,43,214,0.08))' }}>
                  <tr>
                    <th className="sophia-scan sophia-terminal-label px-4 py-3 text-left text-sm font-medium" style={{ color: '#ffd78a' }}>Component</th>
                    <th className="sophia-scan sophia-terminal-label px-4 py-3 text-left text-sm font-medium" style={{ color: '#ffb8e9' }}>Vendor</th>
                    <th className="sophia-scan sophia-terminal-label px-4 py-3 text-left text-sm font-medium" style={{ color: '#aef7ff' }}>Version</th>
                    <th className="sophia-scan sophia-terminal-label px-4 py-3 text-left text-sm font-medium" style={{ color: '#b8ffca' }}>Status</th>
                    <th className="sophia-scan sophia-terminal-label px-4 py-3 text-left text-sm font-medium" style={{ color: '#ffd78a' }}>Update</th>
                  </tr>
                </thead>
                <tbody>
                  {firmware.map((fw, idx) => (
                    <motion.tr
                      key={fw.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: idx * 0.05 }}
                      className="border-t border-gray-800 cursor-pointer"
                      style={secureBootRow(idx)}
                      onClick={() => setSelectedComponent(fw)}
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <HardDrive className="h-4 w-4 text-cyan-300" />
                          <span className="sophia-scan sophia-terminal-label font-medium" style={{ color: '#ecfeff' }}>{fw.name}</span>
                        </div>
                      </td>
                      <td className="sophia-flicker sophia-terminal-meta px-4 py-3 text-sm" style={{ color: '#ffd78a' }}>{fw.vendor}</td>
                      <td className="sophia-flicker sophia-terminal-value px-4 py-3 text-sm font-mono" style={{ color: '#ecfeff' }}>{fw.version}</td>
                      <td className="px-4 py-3">
                        <Badge variant={fw.secure ? 'success' : 'destructive'}>
                          {fw.secure ? 'Secure' : 'Vulnerable'}
                        </Badge>
                      </td>
                      <td className="px-4 py-3">
                        {fw.update_available ? (
                          <Badge variant="warning">Available</Badge>
                        ) : (
                          <span className="text-sm" style={{ color: '#d7fbff', opacity: 0.82 }}>Up to date</span>
                        )}
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Alerts View */}
          {viewMode === 'alerts' && (
            <div className="rounded-xl overflow-hidden" style={secureBootPanel('magenta')}>
              <div className="p-4 border-b border-gray-800">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <AlertOctagon className="h-5 w-5 text-orange-400" />
                  Boot Security Alerts
                </h3>
              </div>
              <div className="divide-y divide-gray-800">
                {alerts.map((alert, idx) => (
                  <motion.div
                    key={alert.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.05 }}
                    className="p-4"
                    style={secureBootRow(idx)}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Badge variant={
                          alert.severity === 'critical' ? 'destructive' :
                          alert.severity === 'warning' ? 'warning' :
                          alert.severity === 'info' ? 'default' :
                          'outline'
                        }>
                          {alert.severity}
                        </Badge>
                        <span className="sophia-flicker sophia-terminal-value text-sm font-mono" style={{ color: '#ffd78a' }}>{alert.endpoint}</span>
                      </div>
                      <span className="text-xs" style={{ color: '#d7fbff', opacity: 0.82 }}>
                        {new Date(alert.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-sm">{alert.message}</p>
                  </motion.div>
                ))}
                {alerts.length === 0 && (
                  <div className="p-8 text-center" style={{ color: '#d7fbff', opacity: 0.82 }}>
                    No boot security alerts
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Side Panel */}
        <div className="space-y-4">
          {/* Scan Result */}
          <AnimatePresence>
            {scanResult && (
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                className="rounded-xl p-4"
                style={secureBootPanel('cyan')}
              >
                <h3 className="font-semibold mb-3 flex items-center gap-2">
                  <Activity className="h-4 w-4 text-cyan-400" />
                  Last Scan Result
                </h3>
                <div className="grid grid-cols-2 gap-3 mb-3">
                  <div className="rounded-lg p-3 text-center" style={secureBootPanel('green')}>
                    <p className="sophia-flicker sophia-terminal-value text-xl font-bold text-green-400">{scanResult.verified_components}</p>
                    <p className="sophia-scan sophia-terminal-label text-xs" style={{ color: '#d7ffd4', opacity: 0.92 }}>Verified</p>
                  </div>
                  <div className="rounded-lg p-3 text-center" style={secureBootPanel('orange')}>
                    <p className="sophia-flicker sophia-terminal-value text-xl font-bold text-orange-400">{scanResult.suspicious_components}</p>
                    <p className="sophia-scan sophia-terminal-label text-xs" style={{ color: '#fff0ca', opacity: 0.92 }}>Suspicious</p>
                  </div>
                </div>
                {scanResult.recommendations?.length > 0 && (
                  <div>
                    <p className="sophia-scan sophia-terminal-label text-sm mb-2" style={{ color: '#aef7ff' }}>Recommendations:</p>
                    <ul className="space-y-1">
                      {scanResult.recommendations.map((rec, idx) => (
                        <li key={idx} className="text-xs flex items-start gap-2" style={{ color: '#ecfeff' }}>
                          <ChevronRight className="h-3 w-3 mt-0.5 text-cyan-400 flex-shrink-0" />
                          {rec}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>

          {/* Selected Component */}
          <AnimatePresence>
            {selectedComponent && (
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                className="rounded-xl p-4"
                style={secureBootPanel('orange')}
              >
                <h3 className="font-semibold mb-3 flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-cyan-400" />
                  Component Details
                </h3>
                <div className="space-y-2">
                  <div>
                    <p className="sophia-scan sophia-terminal-label text-xs" style={{ color: '#aef7ff' }}>Name</p>
                    <p className="sophia-flicker sophia-terminal-value font-medium" style={{ color: '#ecfeff' }}>{selectedComponent.name}</p>
                  </div>
                  <div>
                    <p className="sophia-scan sophia-terminal-label text-xs" style={{ color: '#ffd78a' }}>Vendor</p>
                    <p className="sophia-flicker sophia-terminal-meta" style={{ color: '#fff0ca' }}>{selectedComponent.vendor}</p>
                  </div>
                  <div>
                    <p className="sophia-scan sophia-terminal-label text-xs" style={{ color: '#ffb8e9' }}>Version</p>
                    <p className="sophia-flicker sophia-terminal-value font-mono" style={{ color: '#fff0fb' }}>{selectedComponent.version}</p>
                  </div>
                  <div className="flex gap-2 pt-2">
                    <Button size="sm" variant="outline" className="flex-1 border-0" style={secureBootButton('cyan')}>
                      <Eye className="h-3 w-3 mr-1" />
                      Verify
                    </Button>
                    {selectedComponent.update_available && (
                      <Button size="sm" className="flex-1 border-0" style={secureBootButton('orange')}>
                        <TrendingUp className="h-3 w-3 mr-1" />
                        Update
                      </Button>
                    )}
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* MITRE Techniques */}
          <div className="rounded-xl p-4" style={secureBootPanel('magenta')}>
            <h3 className="font-semibold mb-3">Monitored Techniques</h3>
            <div className="space-y-2">
              {[
                { id: 'T1542.001', name: 'System Firmware' },
                { id: 'T1542.003', name: 'Bootkit' },
                { id: 'T1495', name: 'Firmware Corruption' },
                { id: 'T1014', name: 'Rootkit' }
              ].map(tech => (
                <div key={tech.id} className="flex items-center justify-between p-2 rounded-lg" style={secureBootPanel(tech.id === 'T1495' ? 'red' : tech.id === 'T1014' ? 'magenta' : 'cyan')}>
                  <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: '#ecfeff' }}>{tech.name}</span>
                  <Badge variant="outline" className="text-xs font-mono border-0" style={secureBootBadge('orange')}>
                    {tech.id}
                  </Badge>
                </div>
              ))}
            </div>
          </div>

          {/* Quick Actions */}
          <div className="rounded-xl p-4" style={secureBootPanel('cyan')}>
            <h3 className="font-semibold mb-3">Quick Actions</h3>
            <div className="space-y-2">
              <Button variant="outline" className="w-full justify-start border-0" style={secureBootButton('cyan')}>
                <Fingerprint className="h-4 w-4 mr-2" />
                TPM Attestation
              </Button>
              <Button variant="outline" className="w-full justify-start border-0" style={secureBootButton('magenta')}>
                <Key className="h-4 w-4 mr-2" />
                View Keys
              </Button>
              <Button variant="outline" className="w-full justify-start border-0" style={secureBootButton('orange')}>
                <BarChart3 className="h-4 w-4 mr-2" />
                Export Report
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SecureBootPage;
