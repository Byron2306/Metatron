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

function StatCard({ icon: Icon, label, value, sub, color = 'text-blue-400', iconBg = 'bg-blue-500/20', delay = 0 }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
      className="bg-slate-900/60 border border-slate-800 rounded-xl p-4"
    >
      <div className="flex items-center gap-3 mb-3">
        <div className={`p-2 rounded-lg ${iconBg}`}>
          <Icon className={`w-4 h-4 ${color}`} />
        </div>
        <span className="text-slate-400 text-sm">{label}</span>
      </div>
      <p className={`text-xl font-bold ${color}`}>{value ?? '—'}</p>
      {sub && <p className="text-xs text-slate-500 mt-1">{sub}</p>}
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
    setFabricPeers(fabricRes?.data?.peers ?? fabricRes?.data ?? []);
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

  const formationState = formationStatus?.status ?? formationStatus?.status_label ?? 'unverified';
  const kernelMode = kernelStatus?.mode ?? 'unavailable';
  const tpmMode = tpmStatus?.mode ?? attestationStatus?.tpm?.mode ?? 'unavailable';
  const fabricPeerCount = Array.isArray(fabricPeers) ? fabricPeers.length : 0;
  const verifiedPeers = Array.isArray(fabricPeers) ? fabricPeers.filter(p => p.verified || p.is_peer_verified).length : 0;
  const enforcement = enforcementState?.enforcement;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="space-y-1">
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <div className="p-2 bg-purple-500/20 rounded-xl">
              <Brain className="w-6 h-6 text-purple-400" />
            </div>
            Sophia — Sovereign Intelligence
          </h1>
          <p className="text-sm text-slate-400 pl-14">
            ARDA OS constitutional layer · Triune reasoning · Kernel enforcement
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={handleRefresh} disabled={refreshing} className="border-slate-700">
            <RefreshCw className={`w-4 h-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button variant="outline" onClick={handleRunFormation} className="border-purple-700 text-purple-300">
            <ShieldCheck className="w-4 h-4 mr-2" />
            Verify Formation
          </Button>
          <Button
            onClick={handleToggleEnforcement}
            className={enforcement ? 'bg-red-700 hover:bg-red-800' : 'bg-green-700 hover:bg-green-800'}
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
        className={`rounded-xl border p-4 flex items-center gap-4 ${
          formationState === 'lawful'
            ? 'border-green-500/40 bg-green-500/10'
            : formationState === 'unverified'
            ? 'border-amber-500/40 bg-amber-500/10'
            : 'border-red-500/40 bg-red-500/10 animate-pulse'
        }`}
      >
        {formationState === 'lawful' ? (
          <ShieldCheck className="w-8 h-8 text-green-400 shrink-0" />
        ) : formationState === 'unverified' ? (
          <ShieldAlert className="w-8 h-8 text-amber-400 shrink-0" />
        ) : (
          <ShieldOff className="w-8 h-8 text-red-400 shrink-0" />
        )}
        <div>
          <p className={`font-bold text-lg ${statusColor(formationState)}`}>
            Constitutional Formation: {formationState.toUpperCase()}
          </p>
          <p className="text-sm text-slate-400">
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
            <p className="text-xs text-slate-500">Last verified</p>
            <p className="text-xs text-slate-300">{new Date(formationStatus.verified_at).toLocaleString()}</p>
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
          color={tpmMode === 'hardware' ? 'text-green-400' : tpmMode === 'mock' ? 'text-amber-400' : 'text-slate-500'}
          iconBg={tpmMode === 'hardware' ? 'bg-green-500/20' : tpmMode === 'mock' ? 'bg-amber-500/20' : 'bg-slate-700/40'}
          delay={0}
        />
        <StatCard
          icon={Cpu}
          label="Kernel LSM"
          value={kernelMode === 'ring0_armed' ? 'Armed' : kernelMode === 'simulation' ? 'Simulation' : 'Unavailable'}
          sub={kernelStatus?.trusted_workloads !== undefined ? `${kernelStatus.trusted_workloads} trusted workloads` : undefined}
          color={kernelMode === 'ring0_armed' ? 'text-green-400' : kernelMode === 'simulation' ? 'text-amber-400' : 'text-slate-500'}
          iconBg={kernelMode === 'ring0_armed' ? 'bg-green-500/20' : 'bg-amber-500/20'}
          delay={0.05}
        />
        <StatCard
          icon={Network}
          label="Fabric Peers"
          value={`${verifiedPeers} / ${fabricPeerCount}`}
          sub={fabricPeerCount === 0 ? 'No peers discovered' : `${verifiedPeers} TPM-verified`}
          color={fabricPeerCount === 0 ? 'text-slate-500' : verifiedPeers === fabricPeerCount ? 'text-green-400' : 'text-amber-400'}
          iconBg="bg-cyan-500/20"
          delay={0.1}
        />
        <StatCard
          icon={BarChart3}
          label="World Entities"
          value={metatronSummary?.total_entities ?? metatronSummary?.entity_count ?? '—'}
          sub={metatronSummary?.active_campaigns !== undefined ? `${metatronSummary.active_campaigns} active campaigns` : undefined}
          color="text-purple-400"
          iconBg="bg-purple-500/20"
          delay={0.15}
        />
      </div>

      {/* Three columns: Triune | Fabric | Attestation */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

        {/* Triune Intelligence */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
          <h2 className="font-semibold text-white flex items-center gap-2">
            <Brain className="w-4 h-4 text-purple-400" />
            Triune Intelligence
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
            <div key={agent.name} className="flex items-center gap-3 p-3 rounded-lg bg-slate-800/50">
              <div className={`p-2 rounded-lg ${agent.bg}`}>
                <agent.icon className={`w-4 h-4 ${agent.color}`} />
              </div>
              <div className="flex-1 min-w-0">
                <p className="font-medium text-white text-sm">{agent.name}</p>
                <p className="text-xs text-slate-500 truncate">{agent.meta || agent.role}</p>
              </div>
              <Badge variant="outline" className="border-slate-600 text-slate-400 text-xs">active</Badge>
            </div>
          ))}

          {metatronSummary?.active_campaigns > 0 && (
            <div className="mt-2 p-3 rounded-lg bg-orange-500/10 border border-orange-500/30">
              <p className="text-xs text-orange-300 font-medium">
                {metatronSummary.active_campaigns} active campaign{metatronSummary.active_campaigns !== 1 ? 's' : ''} tracked
              </p>
            </div>
          )}
        </div>

        {/* Fabric Peers */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
          <h2 className="font-semibold text-white flex items-center gap-2">
            <Radio className="w-4 h-4 text-cyan-400" />
            Arda Fabric Peers
          </h2>
          {localNode && (
            <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30">
              <p className="text-xs text-cyan-300 font-mono">{localNode.node_id ?? localNode.id ?? 'local'}</p>
              <p className="text-xs text-slate-500">{localNode.hostname ?? 'local node'} · {localNode.wg_pubkey ? 'WireGuard armed' : 'no WG key'}</p>
            </div>
          )}
          {fabricPeers.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-6 text-slate-600">
              <Network className="w-8 h-8 mb-2" />
              <p className="text-sm">No fabric peers discovered</p>
              <p className="text-xs mt-1">Peers join via UDP summons on port 43210</p>
            </div>
          ) : (
            <div className="space-y-2 max-h-56 overflow-auto">
              {fabricPeers.map((peer, i) => (
                <div key={peer.node_id ?? peer.id ?? i} className="flex items-center gap-2 p-2 rounded bg-slate-800/60">
                  <StatusDot status={peer.verified || peer.is_peer_verified ? 'harmonic' : 'unverified'} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-mono text-slate-300 truncate">{peer.node_id ?? peer.id ?? peer.hostname ?? `peer-${i}`}</p>
                    <p className="text-xs text-slate-600">{peer.ip ?? peer.address ?? ''}</p>
                  </div>
                  <Badge
                    variant="outline"
                    className={`text-xs ${peer.verified || peer.is_peer_verified ? 'border-green-600 text-green-400' : 'border-amber-600 text-amber-400'}`}
                  >
                    {peer.verified || peer.is_peer_verified ? 'verified' : 'unverified'}
                  </Badge>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Attestation & Kernel */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
          <h2 className="font-semibold text-white flex items-center gap-2">
            <Shield className="w-4 h-4 text-indigo-400" />
            Attestation &amp; Kernel
          </h2>

          <div className="space-y-3">
            {/* TPM */}
            <div className="flex justify-between items-center py-2 border-b border-slate-800">
              <span className="text-sm text-slate-400">TPM Mode</span>
              <span className={`text-sm font-medium ${tpmMode === 'hardware' ? 'text-green-400' : tpmMode === 'mock' ? 'text-amber-400' : 'text-slate-500'}`}>
                <StatusDot status={tpmMode === 'hardware' ? 'harmonic' : tpmMode} />
                {tpmMode}
              </span>
            </div>

            {/* Secure Boot */}
            {(attestationStatus?.secure_boot !== undefined || formationStatus?.secure_boot_enabled !== undefined) && (
              <div className="flex justify-between items-center py-2 border-b border-slate-800">
                <span className="text-sm text-slate-400">Secure Boot</span>
                <span className={`text-sm font-medium ${(attestationStatus?.secure_boot ?? formationStatus?.secure_boot_enabled) ? 'text-green-400' : 'text-red-400'}`}>
                  {(attestationStatus?.secure_boot ?? formationStatus?.secure_boot_enabled) ? '✓ Enabled' : '✗ Disabled'}
                </span>
              </div>
            )}

            {/* BPF LSM */}
            <div className="flex justify-between items-center py-2 border-b border-slate-800">
              <span className="text-sm text-slate-400">BPF LSM</span>
              <span className={`text-sm font-medium ${statusColor(kernelMode === 'ring0_armed' ? 'armed' : kernelMode)}`}>
                <StatusDot status={kernelMode === 'ring0_armed' ? 'harmonic' : kernelMode} />
                {kernelMode}
              </span>
            </div>

            {/* Enforcement */}
            <div className="flex justify-between items-center py-2 border-b border-slate-800">
              <span className="text-sm text-slate-400">Enforcement</span>
              <span className={`text-sm font-medium ${enforcement ? 'text-green-400' : 'text-slate-500'}`}>
                {enforcement === undefined ? '—' : enforcement ? '✓ On' : '✗ Off'}
              </span>
            </div>

            {/* Sovereign Mode */}
            {kernelStatus?.sovereign_mode !== undefined && (
              <div className="flex justify-between items-center py-2">
                <span className="text-sm text-slate-400">Sovereign Mode</span>
                <span className={`text-sm font-medium ${kernelStatus.sovereign_mode ? 'text-purple-400' : 'text-slate-500'}`}>
                  {kernelStatus.sovereign_mode ? '✓ Active' : 'Inactive'}
                </span>
              </div>
            )}
          </div>

          {/* PCR snapshot if available */}
          {attestationStatus?.pcrs && Object.keys(attestationStatus.pcrs).length > 0 && (
            <div className="mt-2">
              <p className="text-xs text-slate-500 mb-2">PCR Snapshot</p>
              <div className="bg-slate-950 rounded p-2 max-h-28 overflow-auto">
                {Object.entries(attestationStatus.pcrs).slice(0, 8).map(([k, v]) => (
                  <div key={k} className="flex gap-2 text-xs font-mono">
                    <span className="text-slate-500 w-8">PCR{k}</span>
                    <span className="text-slate-300 truncate">{String(v).slice(0, 32)}…</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Formation detail */}
      {formationStatus && formationStatus.status !== 'unverified' && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
          <h2 className="font-semibold text-white mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-green-400" />
            Formation Verification Detail
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'PCR Constraints', value: formationStatus.pcr_satisfied ? '✓ Satisfied' : '✗ Failed', ok: formationStatus.pcr_satisfied },
              { label: 'Secure Boot', value: formationStatus.secure_boot_enabled ? '✓ Enabled' : '✗ Disabled', ok: formationStatus.secure_boot_enabled },
              { label: 'Manifest', value: formationStatus.manifest_valid ? '✓ Valid' : formationStatus.manifest_valid === false ? '✗ Invalid' : '—', ok: formationStatus.manifest_valid },
              { label: 'Formation', value: formationState.toUpperCase(), ok: formationState === 'lawful' },
            ].map(({ label, value, ok }) => (
              <div key={label} className={`p-3 rounded-lg border ${ok ? 'border-green-500/30 bg-green-500/10' : ok === false ? 'border-red-500/30 bg-red-500/10' : 'border-slate-700 bg-slate-800/40'}`}>
                <p className="text-xs text-slate-500">{label}</p>
                <p className={`text-sm font-medium mt-1 ${ok ? 'text-green-400' : ok === false ? 'text-red-400' : 'text-slate-400'}`}>{value}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
