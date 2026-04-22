import { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { Badge } from './ui/badge';
import { AlertTriangle, Cpu, Fingerprint, ShieldCheck } from 'lucide-react';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const API_BASE = API.endsWith('/api') ? API.slice(0, -4) : API;
const API_V1 = `${API_BASE}/api/v1`;

const pill = (tone) => {
  if (tone === 'good') return 'bg-green-500/20 text-green-300 border border-green-500/30';
  if (tone === 'warn') return 'bg-amber-500/20 text-amber-200 border border-amber-500/30';
  if (tone === 'bad') return 'bg-red-500/20 text-red-200 border border-red-500/30';
  return 'bg-slate-500/20 text-slate-200 border border-slate-500/30';
};

export default function RealityBanner() {
  const { getAuthHeaders } = useAuth();
  const headers = useMemo(() => ({ headers: getAuthHeaders() }), [getAuthHeaders]);

  const [attestation, setAttestation] = useState(null);
  const [kernel, setKernel] = useState(null);
  const [secureBoot, setSecureBoot] = useState(null);

  useEffect(() => {
    let cancelled = false;
    const fetchAll = async () => {
      try {
        const [attRes, kerRes, sbRes] = await Promise.allSettled([
          axios.get(`${API}/attestation/status`, headers),
          axios.get(`${API}/kernel/status`, headers),
          axios.get(`${API_V1}/secure-boot/status`, headers),
        ]);

        if (!cancelled) {
          if (attRes.status === 'fulfilled') setAttestation(attRes.value.data);
          if (kerRes.status === 'fulfilled') setKernel(kerRes.value.data);
          if (sbRes.status === 'fulfilled') setSecureBoot(sbRes.value.data);
        }
      } catch {
        // best-effort banner; ignore
      }
    };

    fetchAll();
    const interval = setInterval(fetchAll, 30000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [headers]);

  const tpmMode = (attestation?.tpm_mode || '').toLowerCase();
  const tpmTone = tpmMode === 'hardware' ? 'good' : tpmMode === 'mock' ? 'warn' : 'neutral';
  const tpmLabel = tpmMode ? `TPM: ${tpmMode.toUpperCase()}` : 'TPM: UNKNOWN';

  const kernelMode = (kernel?.mode || '').toLowerCase();
  const kernelTone = kernelMode === 'ring0_armed' ? 'good' : kernelMode === 'simulation' ? 'warn' : 'neutral';
  const kernelLabel = kernelMode ? `Kernel: ${kernelMode.replace(/_/g, ' ').toUpperCase()}` : 'Kernel: UNKNOWN';

  const sbAvailable = secureBoot?.measurement_available;
  const sbState = (secureBoot?.secure_boot_state || '').toLowerCase();
  const sbLabel =
    sbAvailable === false ? 'Secure Boot: UNAVAILABLE' :
    sbState === 'enabled' ? 'Secure Boot: ENABLED' :
    sbState === 'disabled' ? 'Secure Boot: DISABLED' :
    'Secure Boot: UNKNOWN';
  const sbTone =
    sbAvailable === false ? 'warn' :
    sbState === 'enabled' ? 'good' :
    sbState === 'disabled' ? 'bad' :
    'neutral';

  const showNote = tpmMode === 'mock' || kernelMode === 'simulation' || sbAvailable === false;

  return (
    <div
      className="px-6 py-3 border-b"
      style={{ backgroundColor: 'rgba(15,23,42,0.6)', borderColor: 'rgba(148,163,184,0.2)' }}
      data-testid="reality-banner"
    >
      <div className="flex flex-wrap items-center gap-2 justify-between">
        <div className="flex flex-wrap items-center gap-2">
          <Badge className={pill(tpmTone)}>
            <Fingerprint className="w-3 h-3 mr-1" />
            {tpmLabel}
          </Badge>
          <Badge className={pill(kernelTone)}>
            <Cpu className="w-3 h-3 mr-1" />
            {kernelLabel}
          </Badge>
          <Badge className={pill(sbTone)}>
            <ShieldCheck className="w-3 h-3 mr-1" />
            {sbLabel}
          </Badge>
        </div>

        {showNote && (
          <div className="text-xs text-slate-300 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-300" />
            <span>
              Demo transparency: MOCK/SIMULATION/UNAVAILABLE indicators are intentional (not silently “greenwashed”).
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

