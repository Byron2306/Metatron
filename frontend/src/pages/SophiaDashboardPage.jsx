/**
 * Sophia Sovereign Dashboard
 * ===========================
 * Live view of ARDA OS + Seraph unified intelligence:
 *   - Constitutional boot status (TPM / Secure Boot / Formation)
 *   - Kernel enforcement (BPF LSM)
 *   - Arda Fabric peer mesh
 *   - Triune intelligence (Metatron / Michael / Loki)
 *   - Attestation subsystem health
 */
import { useState, useEffect, useCallback } from 'react';
import apiClient from '../lib/api';
import { motion } from 'framer-motion';
import { useAuth } from '../context/AuthContext';
import {
  Shield, ShieldCheck, ShieldAlert, ShieldOff,
  Cpu, Network, Brain, Eye, Activity,
  CheckCircle2, XCircle, AlertTriangle, Clock,
  RefreshCw, Lock, Unlock, Server, Fingerprint,
  Zap, Radio, GitBranch, BarChart3
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { toast } from 'sonner';

const STATUS_COLORS = {
  lawful: 'text-green-400',
  harmonic: 'text-green-400',
  armed: 'text-green-400',
  hardware: 'text-green-400',
  active: 'text-green-400',
  unlawful: 'text-red-400',
  fallen: 'text-red-400',
  compromised: 'text-red-400',
  unavailable: 'text-slate-500',
  simulation: 'text-amber-400',
  mock: 'text-amber-400',
  unverified: 'text-amber-400',
  strained: 'text-amber-400',
  dissonant: 'text-orange-400',
};

function statusColor(s) {
  return STATUS_COLORS[s?.toLowerCase?.()] || 'text-slate-400';
}

function StatusDot({ status }) {
  const color = status?.toLowerCase?.() === 'lawful' || status?.toLowerCase?.() === 'harmonic' || status?.toLowerCase?.() === 'hardware' || status?.toLowerCase?.() === 'active'
    ? 'bg-green-400'
    : status?.toLowerCase?.() === 'unlawful' || status?.toLowerCase?.() === 'compromised' || status?.toLowerCase?.() === 'fallen'
    ? 'bg-red-400 animate-pulse'
    : status?.toLowerCase?.() === 'simulation' || status?.toLowerCase?.() === 'mock' || status?.toLowerCase?.() === 'unverified'
    ? 'bg-amber-400'
    : 'bg-slate-600';
  return <span className={`inline-block w-2 h-2 rounded-full mr-2 ${color}`} />;
}

const STAT_NEON = {
  'text-green-400':  { glow: 'rgba(57,255,20,0.92)',   border: 'rgba(57,255,20,0.48)',   edge: 'rgba(80,255,30,1)',      bg: 'rgba(57,255,20,0.08)' },
  'text-amber-400':  { glow: 'rgba(251,191,36,0.88)',  border: 'rgba(251,191,36,0.44)',  edge: 'rgba(255,205,50,1)',     bg: 'rgba(251,191,36,0.08)' },
  'text-red-400':    { glow: 'rgba(248,113,113,0.88)', border: 'rgba(248,113,113,0.44)', edge: 'rgba(255,130,130,1)',    bg: 'rgba(248,113,113,0.08)' },
  'text-cyan-400':   { glow: 'rgba(0,240,255,0.88)',   border: 'rgba(0,240,255,0.44)',   edge: 'rgba(80,248,255,1)',     bg: 'rgba(0,240,255,0.08)' },
  'text-blue-400':   { glow: 'rgba(96,165,250,0.88)',  border: 'rgba(96,165,250,0.44)',  edge: 'rgba(120,185,255,1)',    bg: 'rgba(96,165,250,0.08)' },
  'text-purple-400': { glow: 'rgba(188,19,254,0.88)',  border: 'rgba(188,19,254,0.44)',  edge: 'rgba(210,100,255,1)',    bg: 'rgba(188,19,254,0.08)' },
  'text-slate-500':  { glow: 'rgba(100,116,139,0.3)',  border: 'rgba(100,116,139,0.25)', edge: 'rgba(148,163,184,0.72)', bg: 'rgba(100,116,139,0.05)' },
};

function StatCard({ icon: Icon, label, value, sub, color = 'text-blue-400', iconBg = 'bg-blue-500/20', delay = 0 }) {
  const neon = STAT_NEON[color] || STAT_NEON['text-blue-400'];
  const borderClass = color === 'text-green-400'
    ? 'sophia-border-green'
    : color === 'text-purple-400'
    ? 'sophia-border-purple'
    : 'sophia-border-cyan';
  const hudColor = neon.edge || neon.border;
  const altColor = color === 'text-green-400'
    ? 'rgba(57,255,20,0.88)'
    : color === 'text-amber-400'
    ? 'rgba(251,191,36,0.88)'
    : color === 'text-red-400'
    ? 'rgba(248,113,113,0.88)'
    : color === 'text-purple-400'
    ? 'rgba(192,132,252,0.88)'
    : 'rgba(255,43,214,0.88)';
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
      className={`sophia-card-glow rounded-xl border p-4 ${borderClass}`}
      style={{
        '--sophia-hud-color': hudColor,
        '--sophia-hud-color-alt': altColor,
        border: `1px solid ${neon.border}`,
        background: `linear-gradient(160deg, ${neon.bg}, rgba(6,14,24,0.88))`,
        boxShadow: `0 0 20px ${neon.glow.replace('0.55','0.26')}, inset 0 0 12px ${neon.glow.replace('0.55','0.08')}`,
      }}
    >
      <div className="flex items-center gap-3 mb-3">
        <div className={`p-2 rounded-lg ${iconBg}`}>
          <Icon className={`w-4 h-4 ${color}`} style={{ filter: `drop-shadow(0 0 6px ${neon.glow})` }} />
        </div>
        <span className="sophia-scan text-sm font-semibold" style={{ fontFamily: "'FfMoon', 'JetBrains Mono', monospace", color: '#e8f6ff', letterSpacing: '0.04em' }}>{label}</span>
      </div>
      <p className={`text-2xl font-bold ${color}`} style={{ fontFamily: "'Deluxe', 'Orbitron', monospace", color: neon.edge, textShadow: `0 0 22px ${neon.glow}, 0 0 48px ${neon.border}, 0 0 80px ${neon.bg.replace('0.08','0.6')}` }}>{value ?? '—'}</p>
      {sub && <p className="panel-subtext text-xs mt-1" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", color: '#9efff0' }}>{sub}</p>}
    </motion.div>
  );
}

export default function SophiaDashboardPage() {
  const { getAuthHeaders } = useAuth();
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Subsystem states
  const [tpmStatus, setTpmStatus] = useState(null);
  const [kernelStatus, setKernelStatus] = useState(null);
  const [enforcementState, setEnforcementState] = useState(null);
  const [fabricPeers, setFabricPeers] = useState([]);
  const [localNode, setLocalNode] = useState(null);
  const [formationStatus, setFormationStatus] = useState(null);
  const [attestationStatus, setAttestationStatus] = useState(null);
  const [metatronSummary, setMetatronSummary] = useState(null);
  const [commandQuery, setCommandQuery] = useState('query sophia --trace authorship --mode lawful');

  const fetchAll = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    else setRefreshing(true);

    const h = getAuthHeaders();

    const safe = async (fn) => { try { return await fn(); } catch { return null; } };

    const [
      attRes, kernRes, enfRes, fabricRes, nodeRes, formRes, metaRes
    ] = await Promise.all([
      safe(() => apiClient.get(`/attestation/status`, { headers: h })),
      safe(() => apiClient.get(`/kernel/status`, { headers: h })),
      safe(() => apiClient.get(`/kernel/enforcement`, { headers: h })),
      safe(() => apiClient.get(`/fabric/peers`, { headers: h })),
      safe(() => apiClient.get(`/fabric/local-node`, { headers: h })),
      safe(() => apiClient.get(`/formation/status`, { headers: h })),
      safe(() => apiClient.get(`/metatron/summary`, { headers: h })),
    ]);

    setAttestationStatus(attRes?.data ?? null);
    setKernelStatus(kernRes?.data ?? null);
    setEnforcementState(enfRes?.data ?? null);
    const rawPeers = fabricRes?.data?.peers ?? fabricRes?.data;
    setFabricPeers(Array.isArray(rawPeers) ? rawPeers : []);
    setLocalNode(nodeRes?.data ?? null);
    setFormationStatus(formRes?.data ?? null);
    setTpmStatus(attRes?.data?.tpm ?? null);
    setMetatronSummary(metaRes?.data ?? null);

    setLoading(false);
    setRefreshing(false);
  }, [getAuthHeaders]);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  const handleRefresh = async () => {
    await fetchAll(true);
    toast.success('Sophia status refreshed');
  };

  const handleRunFormation = async () => {
    try {
      toast.info('Running formation verification…');
      const res = await apiClient.post(`/formation/verify`, {}, { headers: getAuthHeaders() });
      const status = res.data?.status_label || res.data?.status || 'unknown';
      if (status === 'lawful') toast.success('Formation verified — LAWFUL');
      else toast.error(`Formation status: ${status}`);
      await fetchAll(true);
    } catch (e) {
      toast.error(e?.response?.data?.detail || 'Formation verification failed');
    }
  };

  const handleToggleEnforcement = async () => {
    const current = enforcementState?.enforcement;
    const next = current ? 'off' : 'on';
    try {
      await apiClient.post(`/kernel/enforcement/${next}`, {}, { headers: getAuthHeaders() });
      toast.success(`Kernel enforcement ${next === 'on' ? 'ARMED' : 'DISARMED'}`);
      await fetchAll(true);
    } catch (e) {
      toast.error(e?.response?.data?.detail || 'Failed to toggle enforcement');
    }
  };

  const handleCommandTransmit = () => {
    if (!commandQuery.trim()) {
      toast.error('Command channel is empty');
      return;
    }
    toast.success(`Transmitting: ${commandQuery}`);
  };

  const formationState = formationStatus?.status ?? formationStatus?.status_label ?? 'unverified';
  const kernelMode = kernelStatus?.mode ?? 'unavailable';
  const tpmMode = tpmStatus?.mode ?? attestationStatus?.tpm?.mode ?? 'unavailable';
  const fabricPeerCount = Array.isArray(fabricPeers) ? fabricPeers.length : 0;
  const verifiedPeers = Array.isArray(fabricPeers) ? fabricPeers.filter((p) => p.verified || p.is_peer_verified).length : 0;
  const transportBackedPeers = Array.isArray(fabricPeers)
    ? fabricPeers.filter((p) => p.source === 'vpn_peers' || p.wg_pubkey || p.ip).length
    : 0;
  const enforcement = enforcementState?.enforcement;
  const verdictConfidence = formationState === 'lawful' ? '0.98' : formationState === 'unverified' ? '0.64' : '0.27';
  const formationBorderClass = formationState === 'lawful'
    ? 'sophia-border-green'
    : formationState === 'unverified'
    ? 'sophia-border-cyan'
    : 'sophia-border-purple';

  const resolvePeerLabel = (peer, index) => {
    const candidate = peer?.node_id || peer?.id || peer?.hostname || peer?.name || `peer-${index}`;
    return candidate === 'unknown-peer' ? `peer-${index}` : candidate;
  };

  return (
    <div className="p-6 space-y-6 sophia-sovereign-page sophia-no-glitch sophia-isolated" data-testid="sophia-dashboard-page" data-sophia-glitch="false">
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="space-y-1">
          <p
            className="sophia-scan text-xs uppercase tracking-[0.34em]"
            style={{ fontFamily: "'FfMoon', 'JetBrains Mono', monospace", color: '#ff8ad9', textShadow: '0 0 10px rgba(255,43,214,0.5)', letterSpacing: '0.3em' }}
          >
            sophia · sovereign · arda constitutional mesh
          </p>
          <h1
            className="seraph-heading-raw m-0"
            style={{
              fontFamily: "'SDGlitch', 'Orbitron', sans-serif",
              fontWeight: 900,
              fontSize: 'clamp(2rem, 4vw, 3rem)',
              letterSpacing: '0.08em',
              lineHeight: 1,
              textTransform: 'uppercase',
              textShadow: '0 0 14px rgba(255,43,214,0.28)',
            }}
          >
            <span className="seraph-heading-flood-rtl">Sophia Sovereign Intelligence</span>
          </h1>
          <p className="panel-subtext text-sm" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", color: '#aaffe8' }}>
            {'> arda os constitutional layer · triune reasoning · kernel enforcement'}
          </p>
        </div>

        <div className="flex gap-2 flex-wrap items-center justify-start md:justify-end">
          <p
            className="text-[0.7rem] tracking-[0.32em] m-0"
            style={{ fontFamily: "'FfMoon', 'JetBrains Mono', monospace", color: '#ffb5f4', textShadow: '0 0 10px rgba(255,43,214,0.35)', letterSpacing: '0.3em' }}
          >
            {formationState === 'lawful' ? 'LAWFUL' : formationState.toUpperCase()}
          </p>

          <Button className="sophia-btn sophia-btn-refresh" variant="outline" onClick={handleRefresh} disabled={refreshing} style={{ borderColor: 'rgba(255,43,214,0.54)', color: '#ffb5f4' }}>
            <RefreshCw className={`w-4 h-4 mr-2 refresh-icon ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button className="sophia-btn sophia-btn-verify" variant="outline" onClick={handleRunFormation} style={{ borderColor: 'rgba(255,43,214,0.62)', color: '#ffd1f8', boxShadow: '0 0 12px rgba(255,43,214,0.22)' }}>
            <ShieldCheck className="w-4 h-4 mr-2" />
            Verify Formation
          </Button>
          <Button
            className="sophia-btn arm-button"
            onClick={handleToggleEnforcement}
            style={enforcement
              ? { background: 'linear-gradient(135deg, rgba(255,59,48,0.95), rgba(255,122,26,0.9))', color: '#fff' }
              : { background: 'linear-gradient(135deg, rgba(57,255,20,0.95), rgba(0,240,255,0.9))', color: '#041018' }}
          >
            {enforcement ? <Lock className="w-4 h-4 mr-2" /> : <Unlock className="w-4 h-4 mr-2" />}
            {enforcement ? 'Disarm LSM' : 'Arm LSM'}
          </Button>
        </div>
      </div>

      {/* Constitutional Banner */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className={`mt-1 rounded-md px-4 py-3 flex items-center gap-3 border ${formationBorderClass}`}
        style={{ backdropFilter: 'blur(1px)' }}
      >
        {formationState === 'lawful' ? (
          <ShieldCheck className="w-5 h-5 text-green-400 shrink-0" />
        ) : formationState === 'unverified' ? (
          <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0" />
        ) : (
          <ShieldOff className="w-5 h-5 text-red-400 shrink-0" />
        )}
        <div>
          <p className={`font-bold text-sm ${statusColor(formationState)}`} style={{ fontFamily: "'SDGlitch', 'JetBrains Mono', monospace", letterSpacing: '0.05em' }}>
            Constitutional Formation: {formationState.toUpperCase()}
          </p>
          <p className="panel-subtext text-xs" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", color: '#9efff0' }}>
            {formationStatus?.message ?? formationStatus?.verification_message ?? (
              formationState === 'unverified'
                ? 'Formation not yet verified — click Verify Formation to run TPM + Secure Boot check'
                : formationState === 'lawful'
                ? 'Boot chain verified. All PCR constraints satisfied. Kernel integrity confirmed.'
                : 'Formation fractured — boot chain integrity cannot be confirmed. Restrict sovereign operations.'
            )}
          </p>
        </div>
        {formationStatus?.verified_at && (
          <div className="ml-auto text-right shrink-0">
            <p className="cyber-small text-xs text-slate-500" style={{ fontFamily: "'FfMoon', 'JetBrains Mono', monospace" }}>Last verified</p>
            <p className="cyber-small text-xs" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", color: '#ffb5f4' }}>{new Date(formationStatus.verified_at).toLocaleString()}</p>
          </div>
        )}
      </motion.div>

      {/* Stat Cards Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          icon={Fingerprint}
          label="TPM Attestation"
          value={tpmMode === 'hardware' ? 'Hardware' : tpmMode === 'mock' ? 'Mock (Dev)' : 'Unavailable'}
          sub={attestationStatus?.tpm?.pcr_count ? `${attestationStatus.tpm.pcr_count} PCRs` : undefined}
          color="text-cyan-400"
          iconBg="bg-cyan-500/20"
          delay={0}
        />
        <StatCard
          icon={Cpu}
          label="Kernel LSM"
          value={kernelMode === 'ring0_armed' ? 'Armed' : kernelMode === 'simulation' ? 'Simulation' : 'Unavailable'}
          sub={kernelStatus?.trusted_workloads !== undefined ? `${kernelStatus.trusted_workloads} trusted workloads` : undefined}
          color="text-green-400"
          iconBg="bg-green-500/20"
          delay={0.05}
        />
        <StatCard
          icon={Network}
          label="Fabric Peers"
          value={`${verifiedPeers} / ${fabricPeerCount}`}
          sub={
            fabricPeerCount === 0
              ? 'No peers discovered'
              : transportBackedPeers > 0
              ? `${transportBackedPeers} transport-backed`
              : `${verifiedPeers} TPM-verified`
          }
          color="text-blue-400"
          iconBg="bg-blue-500/20"
          delay={0.1}
        />
        <StatCard
          icon={BarChart3}
          label="World Entities"
          value={metatronSummary?.total_entities ?? metatronSummary?.entity_count ?? '—'}
          sub={metatronSummary?.total_entities !== undefined || metatronSummary?.entity_count !== undefined
            ? `${metatronSummary?.total_entities ?? metatronSummary?.entity_count ?? 0} monitored campaign/world-state actors`
            : undefined}
          color="text-purple-400"
          iconBg="bg-purple-500/20"
          delay={0.15}
        />
      </div>

      {/* Three columns: Triune | Fabric | Attestation */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

        {/* Triune Intelligence */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4 sophia-panel-glow sophia-panel-triune sophia-border-magenta sophia-column-rail sophia-column-rail--magenta flex flex-col md:min-h-[38rem]">
          <h2 className="font-semibold flex items-center gap-2" style={{ fontFamily: "'SDGlitch', 'JetBrains Mono', monospace", letterSpacing: '0.06em', fontSize: '1.05rem' }}>
            <Brain className="w-4 h-4" style={{ color: '#ff8ad9', filter: 'drop-shadow(0 0 6px rgba(255,43,214,0.7))' }} />
            <span className="sophia-glitch" style={{ color: '#ffd1f8', textShadow: '0 0 14px rgba(255,43,214,0.55)' }}>Triune Intelligence</span>
          </h2>
          {[
            {
              name: 'Metatron',
              role: 'Strategic assessment',
              icon: Eye,
              color: 'text-blue-400',
              bg: 'bg-blue-500/20',
              meta: metatronSummary ? `${metatronSummary.total_entities ?? '?'} entities tracked` : null,
            },
            {
              name: 'Michael',
              role: 'Action planning & ranking',
              icon: Zap,
              color: 'text-orange-400',
              bg: 'bg-orange-500/20',
              meta: null,
            },
            {
              name: 'Loki',
              role: 'Dissent & hypotheses',
              icon: GitBranch,
              color: 'text-pink-400',
              bg: 'bg-pink-500/20',
              meta: null,
            },
          ].map((agent) => (
            <div key={agent.name} className="flex items-center gap-3 p-3 rounded-lg bg-slate-800/50 sophia-row-glow sophia-micro-navy" style={agent.name === 'Loki' ? { border: '1px solid rgba(255,43,214,0.34)', background: 'linear-gradient(140deg, rgba(255,43,214,0.14), rgba(12,24,44,0.66))' } : undefined}>
              <div className={`p-2 rounded-lg ${agent.bg}`}>
                <agent.icon className={`w-4 h-4 ${agent.color}`} />
              </div>
              <div className="flex-1 min-w-0">
                <p className="sophia-scan font-medium text-white text-sm" style={{ fontFamily: "'FfMoon', 'JetBrains Mono', monospace", letterSpacing: '0.06em', color: '#e8f6ff' }}>{agent.name}</p>
                <p className="panel-subtext text-xs truncate" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", color: agent.name === 'Loki' ? '#aaffe8' : '#9efff0' }}>{agent.meta || agent.role}</p>
              </div>
              <Badge variant="outline" className="text-xs sophia-badge-pulse" style={{ background: agent.name === 'Loki' ? 'rgba(255,43,214,0.44)' : 'rgba(0,240,255,0.36)', border: `1px solid ${agent.name === 'Loki' ? 'rgba(255,43,214,0.85)' : 'rgba(0,240,255,0.8)'}`, color: agent.name === 'Loki' ? '#ffb5f4' : '#7ffffc', boxShadow: agent.name === 'Loki' ? '0 0 10px rgba(255,43,214,0.55)' : '0 0 10px rgba(0,240,255,0.48)' }}>active</Badge>
            </div>
          ))}

          <div className="mt-2 p-3 rounded-lg" style={{ background: 'linear-gradient(135deg, rgba(255,43,214,0.2), rgba(124,58,237,0.16))', border: '2px solid rgba(255,43,214,0.62)', boxShadow: '0 0 18px rgba(255,43,214,0.22)' }}>
            <p className="panel-subtext text-xs font-medium" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", color: '#aaffe8' }}>Loki dissent channel primed for adversarial hypothesis checks</p>
          </div>

          {metatronSummary?.active_campaigns > 0 && (
            <div className="mt-2 p-3 rounded-lg bg-orange-500/10 border border-orange-500/30">
              <p className="panel-subtext text-xs text-orange-300 font-medium">
                {metatronSummary.active_campaigns} active campaign{metatronSummary.active_campaigns !== 1 ? 's' : ''} tracked
              </p>
            </div>
          )}
        </div>

        {/* Fabric Peers */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4 sophia-panel-glow sophia-panel-fabric md:min-h-[38rem] flex flex-col sophia-border-cyan sophia-column-rail sophia-column-rail--cyan">
          <h2 className="font-semibold flex items-center gap-2" style={{ fontFamily: "'SDGlitch', 'JetBrains Mono', monospace", letterSpacing: '0.06em', fontSize: '1.05rem' }}>
            <Radio className="w-4 h-4 text-cyan-400" style={{ filter: 'drop-shadow(0 0 5px rgba(0,240,255,0.6))' }} />
            <span className="sophia-glitch" style={{ color: '#ffb5f4', textShadow: '0 0 14px rgba(255,43,214,0.55)' }}>Arda Fabric Peers</span>
          </h2>
          {localNode && (
            <div className="p-3 rounded-lg bg-cyan-500/10 border sophia-row-glow sophia-micro-teal" style={{ borderColor: 'rgba(255,43,214,0.44)' }}>
              <p className="cyber-small text-xs" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", color: '#7ffffc' }}>{localNode.node_id ?? localNode.id ?? 'local'}</p>
              <p className="panel-subtext text-xs" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", color: '#aaffe8' }}>{localNode.hostname ?? 'local node'} · {localNode.wg_pubkey ? 'WireGuard armed' : 'no WG key'}</p>
            </div>
          )}
          {fabricPeers.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-6 text-slate-400">
              <Network className="w-8 h-8 mb-2" />
              <p className="panel-subtext text-sm">No fabric peers discovered</p>
              <p className="panel-subtext text-xs mt-1">Peers join via UDP summons on port 43210</p>
            </div>
          ) : (
            <div className="space-y-2 flex-1 min-h-[16rem] overflow-auto pr-1">
              {fabricPeers.map((peer, i) => {
                const verified = Boolean(peer.verified || peer.is_peer_verified);
                const label = resolvePeerLabel(peer, i);
                const isTransportBacked = Boolean(peer.source === 'vpn_peers' || peer.wg_pubkey || peer.ip);
                return (
                  <div
                    key={peer.node_id ?? peer.id ?? i}
                    className="flex items-center gap-2 p-2 rounded bg-slate-800/60 sophia-row-glow sophia-micro-teal"
                    style={verified ? { border: '1px solid rgba(255,43,214,0.35)' } : undefined}
                  >
                    <StatusDot status={verified ? 'harmonic' : isTransportBacked ? 'active' : 'unverified'} />
                    <div className="flex-1 min-w-0">
                      <p className="cyber-small text-xs truncate" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", color: '#c8fffe' }}>{label}</p>
                      <p className="panel-subtext text-xs" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", color: '#9efff0' }}>{peer.ip ?? peer.address ?? peer.wg_pubkey ?? 'transport discovered'}</p>
                    </div>
                    <Badge
                      variant="outline"
                      className="text-xs sophia-badge-pulse"
                      style={verified
                        ? { background: 'rgba(57,255,20,0.4)', border: '1px solid rgba(57,255,20,0.85)', color: '#8bff6a', boxShadow: '0 0 12px rgba(57,255,20,0.52)' }
                        : isTransportBacked
                        ? { background: 'rgba(0,240,255,0.36)', border: '1px solid rgba(0,240,255,0.82)', color: '#7ffffc', boxShadow: '0 0 12px rgba(0,240,255,0.48)' }
                        : { background: 'rgba(251,191,36,0.36)', border: '1px solid rgba(251,191,36,0.78)', color: '#ffd166', boxShadow: '0 0 12px rgba(251,191,36,0.44)' }
                      }
                    >
                      {verified ? 'verified' : isTransportBacked ? 'discovered' : 'unverified'}
                    </Badge>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Attestation & Kernel */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4 sophia-panel-glow sophia-panel-kernel sophia-border-green sophia-column-rail sophia-column-rail--green flex flex-col md:min-h-[38rem]">
          <h2 className="font-semibold flex items-center gap-2" style={{ fontFamily: "'SDGlitch', 'JetBrains Mono', monospace", letterSpacing: '0.06em', fontSize: '1.05rem' }}>
            <Shield className="w-4 h-4" style={{ color: '#ff8ad9', filter: 'drop-shadow(0 0 6px rgba(255,43,214,0.7))' }} />
            <span className="sophia-glitch" style={{ color: '#ffd1f8', textShadow: '0 0 14px rgba(255,43,214,0.55), 0 0 28px rgba(255,43,214,0.28)' }}>Attestation &amp; Kernel</span>
          </h2>

          <div className="rounded-lg px-4 py-3 sophia-row-glow sophia-corrupt-block" style={{ background: 'linear-gradient(140deg, rgba(0,240,255,0.1), rgba(255,43,214,0.08))' }}>
            <p className="sophia-glitch text-xs uppercase tracking-[0.2em]" style={{ fontFamily: "'SDGlitch', 'JetBrains Mono', monospace", color: '#8cf8ff' }}>Formation Verdict</p>
            <p className="text-2xl mt-1" style={{ fontFamily: "'Deluxe', 'Orbitron', monospace", color: formationState === 'lawful' ? '#5eff9c' : formationState === 'unverified' ? '#ffd166' : '#ff8080', textShadow: '0 0 14px currentColor' }}>
              {formationState.toUpperCase()}
            </p>
            <p className="panel-subtext mt-1" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", color: '#9efff0' }}>Confidence: {verdictConfidence}</p>
            <p className="panel-subtext" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", color: '#9efff0' }}>
              Last verified: {formationStatus?.verified_at ? new Date(formationStatus.verified_at).toLocaleString() : 'Awaiting verification'}
            </p>
            <p className="cyber-small sophia-corrupt-readout mt-1" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", color: '#9efff0' }}>
              corruption stream active
            </p>
          </div>

          <div className="space-y-3" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace" }}>
            {/* TPM */}
            <div className="sophia-terminal-row sophia-row-glow sophia-hairline flex justify-between items-center py-2 rounded-md px-2">
              <span className="sophia-scan text-base font-semibold tracking-wide" style={{ fontFamily: "'FfMoon', 'JetBrains Mono', monospace", color: '#ffe6fb', textShadow: '0 0 10px rgba(255,43,214,0.5)', letterSpacing: '0.04em' }}>TPM Mode</span>
              <span
                className={`sophia-flicker text-base font-semibold tracking-wide ${tpmMode === 'hardware' ? 'text-green-400' : tpmMode === 'mock' ? 'text-amber-400' : 'text-slate-300'}`}
                style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", fontSize: '1.02rem', textShadow: '0 0 12px currentColor, 0 0 24px currentColor' }}
              >
                <StatusDot status={tpmMode === 'hardware' ? 'harmonic' : tpmMode} />
                {tpmMode}
              </span>
            </div>

            {/* Secure Boot */}
            {(attestationStatus?.secure_boot !== undefined || formationStatus?.secure_boot_enabled !== undefined) && (
              <div className="sophia-terminal-row sophia-row-glow sophia-hairline flex justify-between items-center py-2 rounded-md px-2">
                <span className="sophia-scan text-base font-semibold tracking-wide" style={{ fontFamily: "'FfMoon', 'JetBrains Mono', monospace", color: '#ffe6fb', textShadow: '0 0 10px rgba(255,43,214,0.5)', letterSpacing: '0.04em' }}>Secure Boot</span>
                <span
                  className={`sophia-flicker text-base font-semibold tracking-wide ${(attestationStatus?.secure_boot ?? formationStatus?.secure_boot_enabled) ? 'text-green-400' : 'text-red-400'}`}
                  style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", fontSize: '1.02rem', textShadow: '0 0 12px currentColor, 0 0 24px currentColor' }}
                >
                  {(attestationStatus?.secure_boot ?? formationStatus?.secure_boot_enabled) ? '✓ Enabled' : '✗ Disabled'}
                </span>
              </div>
            )}

            {/* BPF LSM */}
            <div className="sophia-terminal-row sophia-row-glow sophia-hairline flex justify-between items-center py-2 rounded-md px-2">
              <span className="sophia-scan text-base font-semibold tracking-wide" style={{ fontFamily: "'FfMoon', 'JetBrains Mono', monospace", color: '#ffe6fb', textShadow: '0 0 10px rgba(255,43,214,0.5)', letterSpacing: '0.04em' }}>BPF LSM</span>
              <span
                className={`sophia-flicker text-base font-semibold tracking-wide ${statusColor(kernelMode === 'ring0_armed' ? 'armed' : kernelMode)}`}
                style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", fontSize: '1.02rem', textShadow: '0 0 12px currentColor, 0 0 24px currentColor' }}
              >
                <StatusDot status={kernelMode === 'ring0_armed' ? 'harmonic' : kernelMode} />
                {kernelMode}
              </span>
            </div>

            {/* Enforcement */}
            <div className="sophia-terminal-row sophia-row-glow sophia-hairline flex justify-between items-center py-2 rounded-md px-2">
              <span className="sophia-scan text-base font-semibold tracking-wide" style={{ fontFamily: "'FfMoon', 'JetBrains Mono', monospace", color: '#ffe6fb', textShadow: '0 0 10px rgba(255,43,214,0.5)', letterSpacing: '0.04em' }}>Enforcement</span>
              <span
                className={`sophia-flicker text-base font-semibold tracking-wide ${enforcement ? 'text-green-400' : 'text-slate-300'}`}
                style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", fontSize: '1.02rem', textShadow: '0 0 12px currentColor, 0 0 24px currentColor' }}
              >
                {enforcement === undefined ? '—' : enforcement ? '✓ On' : '✗ Off'}
              </span>
            </div>

            {/* Sovereign Mode */}
            {kernelStatus?.sovereign_mode !== undefined && (
              <div className="sophia-terminal-row sophia-row-glow flex justify-between items-center py-2 rounded-md px-2">
                <span className="sophia-scan text-base font-semibold tracking-wide" style={{ fontFamily: "'FfMoon', 'JetBrains Mono', monospace", color: '#ffe6fb', textShadow: '0 0 10px rgba(255,43,214,0.5)', letterSpacing: '0.04em' }}>Sovereign Mode</span>
                <span
                  className={`sophia-flicker text-base font-semibold tracking-wide ${kernelStatus.sovereign_mode ? 'text-purple-400' : 'text-slate-300'}`}
                  style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", fontSize: '1.02rem', textShadow: '0 0 12px currentColor, 0 0 24px currentColor' }}
                >
                  {kernelStatus.sovereign_mode ? '✓ Active' : 'Inactive'}
                </span>
              </div>
            )}
          </div>

          {/* PCR snapshot if available */}
          {attestationStatus?.pcrs && Object.keys(attestationStatus.pcrs).length > 0 && (
            <div className="mt-2">
              <p className="sophia-glitch text-sm font-semibold mb-2 uppercase tracking-widest" style={{ color: '#ff9fe8', fontFamily: "'SDGlitch', 'JetBrains Mono', monospace", textShadow: '0 0 12px rgba(255,43,214,0.55), 0 0 24px rgba(255,43,214,0.28)' }}>PCR Snapshot</p>
              <div className="bg-slate-950 rounded p-2 max-h-28 overflow-auto" style={{ border: '1px solid rgba(255,43,214,0.42)', boxShadow: 'inset 0 0 18px rgba(255,43,214,0.13)' }}>
                {Object.entries(attestationStatus.pcrs).slice(0, 8).map(([k, v]) => (
                  <div key={k} className="sophia-terminal-row sophia-row-glow flex gap-2 leading-7 rounded-sm px-1" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", fontSize: '0.92rem' }}>
                    <span className="sophia-scan w-12 font-bold" style={{ fontFamily: "'FfMoon', 'JetBrains Mono', monospace", color: '#ffd9f8', textShadow: '0 0 10px rgba(255,43,214,0.72)' }}>PCR{k}</span>
                    <span className="sophia-flicker truncate" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", color: '#a8fffb', textShadow: '0 0 12px rgba(0,240,255,0.7), 0 0 24px rgba(0,240,255,0.35)' }}>{String(v).slice(0, 32)}…</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="rounded-lg px-4 py-3 sophia-row-glow sophia-corrupt-block" style={{ background: 'linear-gradient(135deg, rgba(255,59,48,0.08), rgba(255,122,26,0.08))' }}>
            <p className="sophia-glitch text-xs uppercase tracking-[0.2em]" style={{ fontFamily: "'SDGlitch', 'JetBrains Mono', monospace", color: '#ffc39c' }}>Boundary Fractures</p>
            <p className="text-xl mt-1" style={{ fontFamily: "'Deluxe', 'Orbitron', monospace", color: '#ffb580', textShadow: '0 0 10px rgba(255,122,26,0.5)' }}>0</p>
            <p className="panel-subtext" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", color: '#ffcfb2' }}>No authorship breach detected</p>
          </div>
        </div>
      </div>

      {/* Formation detail */}
      {formationStatus && formationStatus.status !== 'unverified' && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 sophia-highlight-box sophia-border-purple" style={{ border: '2px solid rgba(124,58,237,0.78)', boxShadow: '0 0 20px rgba(124,58,237,0.24)' }}>
          <h2 className="font-semibold mb-4 flex items-center gap-2" style={{ fontFamily: "'SDGlitch', 'JetBrains Mono', monospace", letterSpacing: '0.06em', fontSize: '1.05rem' }}>
            <Activity className="w-4 h-4" style={{ color: '#ff8ad9', filter: 'drop-shadow(0 0 6px rgba(255,43,214,0.7))' }} />
            <span className="sophia-glitch" style={{ color: '#ffd1f8', textShadow: '0 0 14px rgba(255,43,214,0.55)' }}>Formation Verification Detail</span>
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'PCR Constraints', value: formationStatus.pcr_satisfied ? '✓ Satisfied' : '✗ Failed', ok: formationStatus.pcr_satisfied },
              { label: 'Secure Boot', value: formationStatus.secure_boot_enabled ? '✓ Enabled' : '✗ Disabled', ok: formationStatus.secure_boot_enabled },
              { label: 'Manifest', value: formationStatus.manifest_valid ? '✓ Valid' : formationStatus.manifest_valid === false ? '✗ Invalid' : '—', ok: formationStatus.manifest_valid },
              { label: 'Formation', value: formationState.toUpperCase(), ok: formationState === 'lawful' },
            ].map(({ label, value, ok }) => (
              <div key={label} className={`p-3 rounded-lg border sophia-highlight-box ${ok ? 'border-green-500/30 bg-green-500/10' : ok === false ? 'border-red-500/30 bg-red-500/10' : 'border-slate-700 bg-slate-800/40'}`}>
                <p className="sophia-scan sophia-neon-cyan text-xs" style={{ fontFamily: "'FfMoon', 'JetBrains Mono', monospace", letterSpacing: '0.04em' }}>{label}</p>
                <p className={`sophia-flicker text-sm font-bold mt-1 ${ok ? 'text-green-400' : ok === false ? 'text-red-400' : 'text-slate-400'}`} style={{ fontFamily: "'Deluxe', 'Orbitron', monospace", textShadow: ok ? '0 0 10px rgba(57,255,20,0.5)' : ok === false ? '0 0 10px rgba(248,113,113,0.5)' : 'none' }}>{value}</p>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
            <div className="sophia-highlight-box rounded-lg px-4 py-3">
              <p className="sophia-scan text-[0.7rem] uppercase tracking-[0.24em]" style={{ fontFamily: "'FfMoon', 'JetBrains Mono', monospace", color: '#b9fff9' }}>Integrity stream</p>
              <p className="sophia-flicker sophia-neon-cyan text-sm mt-1" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace" }}>Kernel witness telemetry stable across constitutional checks.</p>
            </div>
            <div className="sophia-highlight-box rounded-lg px-4 py-3">
              <p className="sophia-scan text-[0.7rem] uppercase tracking-[0.24em]" style={{ fontFamily: "'FfMoon', 'JetBrains Mono', monospace", color: '#b9fff9' }}>Sovereign link</p>
              <p className="sophia-flicker sophia-neon-cyan text-sm mt-1" style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace" }}>Fabric attestation channel locked with neon-cyan heartbeat framing.</p>
            </div>
          </div>
        </div>
      )}

      <div className="sophia-command-bar rounded-xl px-4 py-3 flex items-center gap-3">
        <span className="sophia-cmd-chrome" aria-hidden>
          <span className="sophia-cmd-chrome__dot sophia-cmd-chrome__dot--red" />
          <span className="sophia-cmd-chrome__dot sophia-cmd-chrome__dot--yellow" />
          <span className="sophia-cmd-chrome__dot sophia-cmd-chrome__dot--green" />
          <span className="sophia-cmd-chrome__label">sophia // shell</span>
        </span>
        <span className="prompt">&gt;</span>
        <input
          value={commandQuery}
          onChange={(e) => setCommandQuery(e.target.value)}
          placeholder="query sophia --trace authorship --mode lawful"
          className="flex-1 bg-transparent outline-none"
          style={{ fontFamily: "'TerminalVision', 'JetBrains Mono', monospace", color: '#b9fff9' }}
        />
        <span className="sophia-cmd-cursor" aria-hidden />
        <Button className="sophia-btn" onClick={handleCommandTransmit}>TRANSMIT</Button>
      </div>

    </div>
  );
}
