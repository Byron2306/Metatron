import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import apiClient from '../lib/api';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';
import { motion } from 'framer-motion';
import {
  Play,
  RefreshCw,
  Network,
  Eye,
  Search,
  Bug,
  ShieldAlert,
  Activity,
  Terminal,
  FileSearch,
  Database,
  Zap,
  Crosshair,
  Globe,
  HardDrive,
  Layers,
} from 'lucide-react';
import SeraphPageHeader from '../components/SeraphPageHeader';

// Visual identity for each integration tool
const TOOL_META = {
  zeek: {
    icon: Network,
    accent: '#00f0ff',
    blurb: 'Network forensic analysis · protocol-aware logs',
    category: 'NETWORK',
  },
  arkime: {
    icon: FileSearch,
    accent: '#7c3aed',
    blurb: 'Full-PCAP indexed retention · packet hunt',
    category: 'NETWORK',
  },
  suricata: {
    icon: ShieldAlert,
    accent: '#ff8a3c',
    blurb: 'Realtime IDS / IPS · signature matching',
    category: 'IDS',
  },
  amass: {
    icon: Globe,
    accent: '#39ff14',
    blurb: 'Attack-surface mapping · subdomain discovery',
    category: 'RECON',
  },
  bloodhound: {
    icon: Crosshair,
    accent: '#ff2bd6',
    blurb: 'AD attack graph · privilege escalation paths',
    category: 'IDENTITY',
  },
  purplesharp: {
    icon: Zap,
    accent: '#bc13fe',
    blurb: 'Adversary emulation · ATT&CK exec on Windows',
    category: 'EMULATION',
  },
  velociraptor: {
    icon: Eye,
    accent: '#aef0ff',
    blurb: 'DFIR endpoint hunting · VQL queries',
    category: 'DFIR',
  },
  yara: {
    icon: Search,
    accent: '#ffb020',
    blurb: 'Pattern-based file & memory matching',
    category: 'MALWARE',
  },
  trivy: {
    icon: Layers,
    accent: '#39ff14',
    blurb: 'Container/IaC vulnerability scanning',
    category: 'VULN',
  },
  falco: {
    icon: Activity,
    accent: '#ff8a3c',
    blurb: 'Kubernetes runtime threat detection',
    category: 'CONTAINER',
  },
  cuckoo: {
    icon: Bug,
    accent: '#ff2bd6',
    blurb: 'Automated malware sandbox · behavioral capture',
    category: 'SANDBOX',
  },
  clamav: {
    icon: ShieldAlert,
    accent: '#39ff14',
    blurb: 'Open-source AV signature scanning',
    category: 'MALWARE',
  },
  osquery: {
    icon: Database,
    accent: '#00f0ff',
    blurb: 'Endpoint state as SQL · live host telemetry',
    category: 'TELEMETRY',
  },
  sysmon: {
    icon: HardDrive,
    accent: '#bc13fe',
    blurb: 'Windows process / registry / network sysevents',
    category: 'TELEMETRY',
  },
  default: {
    icon: Terminal,
    accent: '#00f0ff',
    blurb: 'Integration tool',
    category: 'TOOL',
  },
};

const toolMeta = (name) => TOOL_META[String(name || '').toLowerCase()] || TOOL_META.default;

const parseJsonOrNull = (value) => {
  const trimmed = String(value || '').trim();
  if (!trimmed) return {};
  try {
    return JSON.parse(trimmed);
  } catch {
    return null;
  }
};

const STATUS_COLOR = {
  success: '#39ff14',
  completed: '#39ff14',
  running: '#00f0ff',
  pending: '#ffb020',
  failed: '#ff3838',
  error: '#ff3838',
};

const statusColor = (s) => STATUS_COLOR[String(s || '').toLowerCase()] || '#9ed3e6';

const FALLBACK_RUNTIME_TOOLS = [
  'amass',
  'arkime',
  'atomic',
  'bloodhound',
  'clamav',
  'cuckoo',
  'falco',
  'osquery',
  'purplesharp',
  'sigma',
  'spiderfoot',
  'suricata',
  'trivy',
  'velociraptor',
  'yara',
  'zeek',
];

export default function IntegrationDiagnosticsPage({
  allowedTools = null,
  defaultTool = 'zeek',
  title = 'Integration Diagnostics',
  description = 'Run the same integration tools the local agent uses, server-side or against a connected agent.',
}) {
  const [tools, setTools] = useState(FALLBACK_RUNTIME_TOOLS);
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [lastRun, setLastRun] = useState(null);
  const [authRestricted, setAuthRestricted] = useState(false);

  const [tool, setTool] = useState(defaultTool);
  const [runtimeTarget, setRuntimeTarget] = useState('server');
  const [agentId, setAgentId] = useState('');
  const [paramsJson, setParamsJson] = useState('{}');
  const authNoticeShownRef = useRef(false);

  const sortedTools = useMemo(() => {
    const all = [...tools].sort();
    if (!Array.isArray(allowedTools) || allowedTools.length === 0) return all;
    const allowed = new Set(allowedTools.map((item) => String(item).toLowerCase()));
    const filtered = all.filter((item) => allowed.has(String(item).toLowerCase()));
    const ordered = allowedTools
      .filter((item) => filtered.some((found) => String(found).toLowerCase() === String(item).toLowerCase()))
      .map((item) => filtered.find((found) => String(found).toLowerCase() === String(item).toLowerCase()));
    const remainder = filtered.filter((item) => !ordered.includes(item));
    return [...ordered, ...remainder];
  }, [tools, allowedTools]);

  useEffect(() => {
    if (sortedTools.length && !sortedTools.includes(tool)) setTool(sortedTools[0]);
  }, [sortedTools, tool]);

  const refresh = useCallback(async () => {
    try {
      const [toolsResult, jobsResult] = await Promise.allSettled([
        apiClient.get('/integrations/runtime/tools'),
        apiClient.get('/integrations/jobs'),
      ]);

      if (toolsResult.status === 'fulfilled') {
        const loadedTools = toolsResult.value?.data?.tools;
        if (Array.isArray(loadedTools) && loadedTools.length) {
          setTools(loadedTools);
        } else {
          const fallback = Array.isArray(allowedTools) && allowedTools.length ? allowedTools : FALLBACK_RUNTIME_TOOLS;
          setTools(fallback);
        }
      } else {
        const status = toolsResult.reason?.response?.status;
        const fallback = Array.isArray(allowedTools) && allowedTools.length ? allowedTools : FALLBACK_RUNTIME_TOOLS;
        setTools((prev) => (prev.length ? prev : fallback));

        if (status === 401 || status === 403) {
          setAuthRestricted(true);
        }

        if ((status === 401 || status === 403) && !authNoticeShownRef.current) {
          authNoticeShownRef.current = true;
          toast.warning('Integration tools endpoint is restricted. Showing fallback tool catalog.');
        }
      }

      if (jobsResult.status === 'fulfilled') {
        const payload = jobsResult.value?.data;
        if (Array.isArray(payload)) {
          setJobs(payload);
        } else {
          setJobs(payload?.jobs || payload?.executions || []);
        }
      } else {
        const status = jobsResult.reason?.response?.status;
        if (status === 401 || status === 403) {
          setAuthRestricted(true);
        }
      }
    } catch (e) {
      // soft-fail; keep cached data
    } finally {
      setLoading(false);
    }
  }, [allowedTools]);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 8000);
    return () => clearInterval(id);
  }, [refresh]);

  const runTool = async () => {
    const params = parseJsonOrNull(paramsJson);
    if (params == null) {
      toast.error('Params must be valid JSON');
      return;
    }
    setRunning(true);
    try {
      const payload = { tool, params, runtime_target: runtimeTarget, agent_id: agentId || null };
      const res = await apiClient.post('/integrations/runtime/run', payload);
      setLastRun(res.data || null);
      toast.success(`Launched ${tool} (${res.data?.job_id || 'job'})`);
      await refresh();
    } catch (e) {
      toast.error(e?.response?.data?.detail || 'Failed to launch tool');
    } finally {
      setRunning(false);
    }
  };

  const selectedMeta = toolMeta(tool);
  const SelectedIcon = selectedMeta.icon;

  return (
    <div className="p-6 lg:p-8 space-y-6 relative">
      <SeraphPageHeader
        eyebrow="integration · diagnostics"
        title={title}
        tagline={`> ${description}`}
        accent="cyan"
        status={`${sortedTools.length} TOOLS · ${jobs.length} JOBS`}
        actions={(
          <div className="flex items-center gap-3">
          <Button className="seraph-btn" onClick={refresh} disabled={loading} style={{ borderRadius: 0, padding: '0.55rem 1rem' }}>
            <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          </div>
        )}
      />

      {authRestricted ? (
        <div
          className="p-3"
          style={{
            background: 'linear-gradient(90deg, rgba(255,176,32,0.18), rgba(255,43,214,0.1))',
            border: '1px solid rgba(255,176,32,0.45)',
            color: '#ffd7a3',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 11,
            letterSpacing: '0.04em',
          }}
        >
          AUTH WARNING: backend integration endpoints are restricted for your current session. Showing local fallback tools until auth is restored.
        </div>
      ) : null}

      {/* === TOOL CATALOG GRID ================================ */}
      <div
        className="seraph-corner-brackets relative p-5"
        style={{
          background: 'linear-gradient(160deg, rgba(9,18,38,0.86), rgba(2,8,19,0.92))',
          border: '1px solid rgba(0,240,255,0.32)',
          boxShadow: 'inset 0 0 18px rgba(0,240,255,0.05), 0 0 18px rgba(0,240,255,0.08)',
        }}
      >
        <span className="seraph-corner-tl" />
        <span className="seraph-corner-tr" />
        <span className="seraph-corner-bl" />
        <span className="seraph-corner-br" />

        <div className="flex items-center gap-3 mb-4">
          <Layers className="w-4 h-4" style={{ color: 'var(--neon-cyan)', filter: 'drop-shadow(0 0 6px rgba(0,240,255,0.6))' }} />
          <h3 style={{
            fontFamily: "'Orbitron', monospace",
            fontWeight: 700,
            letterSpacing: '0.16em',
            textTransform: 'uppercase',
            fontSize: 13,
            color: '#e6fbff',
            margin: 0,
            textShadow: '0 0 8px rgba(0,240,255,0.4)',
          }}>
            Tool Catalog
          </h3>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 xl:grid-cols-6 gap-3">
          {sortedTools.length === 0 && !loading ? (
            <div className="col-span-full text-center py-6" style={{ color: '#9ed3e6', fontFamily: "'JetBrains Mono', monospace", fontSize: 12, letterSpacing: '0.06em' }}>
              &gt; no integration tools registered
            </div>
          ) : null}
          {sortedTools.map((name, i) => {
            const meta = toolMeta(name);
            const Icon = meta.icon;
            const isActive = tool === name;
            return (
              <motion.button
                key={name}
                type="button"
                onClick={() => setTool(name)}
                whileHover={{ y: -3 }}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.025 }}
                className="relative p-3 text-left transition-all"
                style={{
                  background: isActive
                    ? `linear-gradient(160deg, ${meta.accent}1a, rgba(2,8,19,0.92))`
                    : 'linear-gradient(160deg, rgba(9,18,38,0.7), rgba(2,8,19,0.86))',
                  border: `1px solid ${isActive ? meta.accent : meta.accent + '44'}`,
                  boxShadow: isActive
                    ? `0 0 18px ${meta.accent}66, inset 0 0 14px ${meta.accent}22`
                    : `inset 0 0 8px ${meta.accent}0a`,
                  clipPath: 'polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px)',
                  cursor: 'pointer',
                  minHeight: 110,
                }}
              >
                <div className="flex items-center justify-between mb-2">
                  <div
                    className="flex items-center justify-center"
                    style={{
                      width: 28,
                      height: 28,
                      background: `${meta.accent}1a`,
                      border: `1px solid ${meta.accent}66`,
                      boxShadow: isActive ? `0 0 10px ${meta.accent}88` : 'none',
                    }}
                  >
                    <Icon className="w-4 h-4" style={{ color: meta.accent, filter: `drop-shadow(0 0 4px ${meta.accent}88)` }} />
                  </div>
                  <span
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 8,
                      letterSpacing: '0.2em',
                      color: meta.accent,
                      opacity: 0.8,
                    }}
                  >
                    {meta.category}
                  </span>
                </div>
                <p
                  style={{
                    fontFamily: "'Orbitron', monospace",
                    fontWeight: 800,
                    fontSize: 13,
                    color: '#e6fbff',
                    letterSpacing: '0.05em',
                    textTransform: 'uppercase',
                    textShadow: isActive ? `0 0 8px ${meta.accent}99` : 'none',
                    margin: 0,
                  }}
                >
                  {name}
                </p>
                <p
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: 9.5,
                    color: '#9ed3e6',
                    letterSpacing: '0.02em',
                    marginTop: 4,
                    lineHeight: 1.35,
                  }}
                >
                  {meta.blurb}
                </p>
                {isActive ? (
                  <span
                    style={{
                      position: 'absolute',
                      top: 8,
                      right: 8,
                      width: 6,
                      height: 6,
                      borderRadius: '50%',
                      background: meta.accent,
                      boxShadow: `0 0 6px ${meta.accent}, 0 0 14px ${meta.accent}aa`,
                    }}
                  />
                ) : null}
              </motion.button>
            );
          })}
        </div>
      </div>

      {/* === LAUNCH PANEL ===================================== */}
      <div
        className="seraph-corner-brackets relative p-5"
        style={{
          background: `linear-gradient(160deg, ${selectedMeta.accent}10, rgba(2,8,19,0.92))`,
          border: `1px solid ${selectedMeta.accent}55`,
          boxShadow: `inset 0 0 18px ${selectedMeta.accent}11, 0 0 22px ${selectedMeta.accent}1a`,
        }}
      >
        <span className="seraph-corner-tl" style={{ borderTopColor: selectedMeta.accent, borderLeftColor: selectedMeta.accent }} />
        <span className="seraph-corner-tr" style={{ borderTopColor: selectedMeta.accent, borderRightColor: selectedMeta.accent }} />
        <span className="seraph-corner-bl" style={{ borderBottomColor: selectedMeta.accent, borderLeftColor: selectedMeta.accent }} />
        <span className="seraph-corner-br" style={{ borderBottomColor: selectedMeta.accent, borderRightColor: selectedMeta.accent }} />

        <div className="flex items-center gap-3 mb-4">
          <div
            className="flex items-center justify-center"
            style={{
              width: 40,
              height: 40,
              background: `${selectedMeta.accent}1a`,
              border: `1px solid ${selectedMeta.accent}88`,
              boxShadow: `0 0 14px ${selectedMeta.accent}66`,
              clipPath: 'polygon(8px 0, 100% 0, 100% calc(100% - 8px), calc(100% - 8px) 100%, 0 100%, 0 8px)',
            }}
          >
            <SelectedIcon className="w-5 h-5" style={{ color: selectedMeta.accent, filter: `drop-shadow(0 0 6px ${selectedMeta.accent}99)` }} />
          </div>
          <div>
            <h3
              style={{
                fontFamily: "'Orbitron', monospace",
                fontWeight: 800,
                fontSize: 18,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                color: selectedMeta.accent,
                textShadow: `0 0 10px ${selectedMeta.accent}aa`,
                margin: 0,
              }}
            >
              {tool || 'select tool'}
            </h3>
            <p style={{ fontSize: 11, color: '#9ed3e6', fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.04em', marginTop: 2 }}>
              {selectedMeta.blurb}
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
          <div>
            <label style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, letterSpacing: '0.32em', color: 'var(--neon-cyan)', textTransform: 'uppercase' }}>
              Runtime
            </label>
            <select
              className="seraph-input mt-1 w-full"
              style={{ padding: '8px 10px', fontSize: 12 }}
              value={runtimeTarget}
              onChange={(e) => setRuntimeTarget(e.target.value)}
            >
              <option value="server">server</option>
              <option value="agent">agent</option>
            </select>
          </div>
          <div>
            <label style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, letterSpacing: '0.32em', color: 'var(--neon-cyan)', textTransform: 'uppercase' }}>
              Agent ID (optional)
            </label>
            <input
              className="seraph-input mt-1 w-full"
              style={{ padding: '8px 10px', fontSize: 12 }}
              value={agentId}
              onChange={(e) => setAgentId(e.target.value)}
              placeholder="unified-agent-id"
            />
          </div>
          <div className="flex items-end">
            <Button
              className="seraph-btn seraph-btn-primary w-full"
              onClick={runTool}
              disabled={running || loading}
              style={{ borderRadius: 0, padding: '0.65rem 1.1rem' }}
            >
              <Play className="w-4 h-4 mr-2" />
              {running ? 'LAUNCHING…' : `EXECUTE ${tool?.toUpperCase() || ''}`}
            </Button>
          </div>
        </div>

        <div>
          <label style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, letterSpacing: '0.32em', color: 'var(--neon-cyan)', textTransform: 'uppercase' }}>
            Params (JSON)
          </label>
          <textarea
            className="seraph-input mt-1 w-full font-mono"
            style={{ minHeight: 96, padding: '8px 10px', fontSize: 11.5, lineHeight: 1.5 }}
            value={paramsJson}
            onChange={(e) => setParamsJson(e.target.value)}
            spellCheck={false}
          />
        </div>
      </div>

      {/* === SPLIT: latest run + jobs ============================== */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Latest response */}
        <div
          className="seraph-corner-brackets relative p-5"
          style={{
            background: 'linear-gradient(160deg, rgba(9,18,38,0.86), rgba(2,8,19,0.92))',
            border: '1px solid rgba(0,240,255,0.32)',
            boxShadow: 'inset 0 0 18px rgba(0,240,255,0.05)',
          }}
        >
          <span className="seraph-corner-tl" />
          <span className="seraph-corner-tr" />
          <span className="seraph-corner-bl" />
          <span className="seraph-corner-br" />

          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4" style={{ color: 'var(--neon-cyan)', filter: 'drop-shadow(0 0 6px rgba(0,240,255,0.6))' }} />
              <h3 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: 13, letterSpacing: '0.18em', textTransform: 'uppercase', color: '#e6fbff', margin: 0, textShadow: '0 0 8px rgba(0,240,255,0.4)' }}>
                Latest Response
              </h3>
            </div>
            <Badge
              variant="outline"
              style={{
                background: lastRun ? 'rgba(57,255,20,0.1)' : 'rgba(0,240,255,0.06)',
                border: `1px solid ${lastRun ? '#39ff14' : 'rgba(0,240,255,0.32)'}`,
                color: lastRun ? '#7fffa6' : '#9ed3e6',
                fontSize: 9,
                letterSpacing: '0.18em',
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              {lastRun ? `JOB ${(lastRun.job_id || '').slice(0, 8) || 'OK'}` : 'IDLE'}
            </Badge>
          </div>
          {lastRun ? (
            <pre
              className="rounded p-3 overflow-auto"
              style={{
                background: 'linear-gradient(160deg, rgba(2,8,19,0.92), rgba(0,6,14,0.95))',
                border: '1px solid rgba(0,240,255,0.18)',
                borderLeft: '2px solid var(--neon-cyan)',
                color: '#b6f5ff',
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 11,
                lineHeight: 1.55,
                maxHeight: 320,
                whiteSpace: 'pre-wrap',
              }}
            >
              {JSON.stringify(lastRun, null, 2)}
            </pre>
          ) : (
            <div
              className="p-4 text-center"
              style={{ color: '#6aa8bc', fontFamily: "'JetBrains Mono', monospace", fontSize: 11.5, letterSpacing: '0.04em' }}
            >
              &gt; execute a tool to populate this buffer
            </div>
          )}
        </div>

        {/* Jobs timeline */}
        <div
          className="seraph-corner-brackets relative p-5"
          style={{
            background: 'linear-gradient(160deg, rgba(9,18,38,0.86), rgba(2,8,19,0.92))',
            border: '1px solid rgba(255,43,214,0.32)',
            boxShadow: 'inset 0 0 18px rgba(255,43,214,0.04)',
          }}
        >
          <span style={{ position: 'absolute', top: -1, left: -1, width: 18, height: 18, borderTop: '2px solid #ff2bd6', borderLeft: '2px solid #ff2bd6', filter: 'drop-shadow(0 0 6px rgba(255,43,214,0.7))' }} />
          <span style={{ position: 'absolute', top: -1, right: -1, width: 18, height: 18, borderTop: '2px solid #ff2bd6', borderRight: '2px solid #ff2bd6', filter: 'drop-shadow(0 0 6px rgba(255,43,214,0.7))' }} />
          <span style={{ position: 'absolute', bottom: -1, left: -1, width: 18, height: 18, borderBottom: '2px solid #ff2bd6', borderLeft: '2px solid #ff2bd6', filter: 'drop-shadow(0 0 6px rgba(255,43,214,0.7))' }} />
          <span style={{ position: 'absolute', bottom: -1, right: -1, width: 18, height: 18, borderBottom: '2px solid #ff2bd6', borderRight: '2px solid #ff2bd6', filter: 'drop-shadow(0 0 6px rgba(255,43,214,0.7))' }} />

          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4" style={{ color: '#ff2bd6', filter: 'drop-shadow(0 0 6px rgba(255,43,214,0.6))' }} />
              <h3 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: 13, letterSpacing: '0.18em', textTransform: 'uppercase', color: '#e6fbff', margin: 0, textShadow: '0 0 8px rgba(255,43,214,0.4)' }}>
                Recent Jobs
              </h3>
            </div>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: '#ff8ad9', letterSpacing: '0.18em' }}>
              {jobs.length}
            </span>
          </div>

          {jobs.length === 0 ? (
            <div className="p-4 text-center" style={{ color: '#6aa8bc', fontFamily: "'JetBrains Mono', monospace", fontSize: 11.5, letterSpacing: '0.04em' }}>
              &gt; no jobs in flight · fire a tool above
            </div>
          ) : (
            <div className="space-y-1.5 overflow-y-auto pr-1" style={{ maxHeight: 360 }}>
              {jobs.slice(0, 30).map((job) => {
                const accent = statusColor(job.status);
                const meta = toolMeta(job.tool || job.name);
                const Icon = meta.icon;
                return (
                  <div
                    key={job.id || job.job_id || JSON.stringify(job).slice(0, 32)}
                    className="flex items-center justify-between gap-3 p-2.5"
                    style={{
                      background: 'linear-gradient(160deg, rgba(9,18,38,0.7), rgba(2,8,19,0.86))',
                      border: `1px solid ${accent}33`,
                      borderLeft: `2px solid ${accent}`,
                    }}
                  >
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <Icon className="w-3.5 h-3.5 flex-shrink-0" style={{ color: meta.accent }} />
                      <div className="min-w-0">
                        <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11.5, color: '#e6fbff', letterSpacing: '0.02em' }}>
                          {job.tool || job.name || 'tool'}
                          <span style={{ color: '#6aa8bc', marginLeft: 8, fontSize: 10 }}>
                            #{(job.id || job.job_id || '').slice(0, 8) || '—'}
                          </span>
                        </p>
                        <p style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 9.5, color: '#9ed3e6' }}>
                          {job.params?.runtime_target || job.runtime_target || 'server'}
                          {job.result?.agent_id || job.agent_id ? ` · agent: ${job.result?.agent_id || job.agent_id}` : ''}
                        </p>
                      </div>
                    </div>
                    <span
                      style={{
                        background: `${accent}1a`,
                        border: `1px solid ${accent}`,
                        color: accent,
                        padding: '2px 8px',
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: 9,
                        letterSpacing: '0.18em',
                        textTransform: 'uppercase',
                        textShadow: `0 0 6px ${accent}99`,
                        clipPath: 'polygon(5px 0, 100% 0, 100% calc(100% - 5px), calc(100% - 5px) 100%, 0 100%, 0 5px)',
                      }}
                    >
                      {job.status || 'unknown'}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
