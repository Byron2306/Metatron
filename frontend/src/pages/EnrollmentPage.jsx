import { useMemo, useState } from "react";
import {
  ArrowRight,
  CheckCircle,
  Copy,
  Download,
  MonitorSmartphone,
  ShieldCheck,
  Sparkles,
  Terminal,
  XCircle,
} from "lucide-react";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { Badge } from "../components/ui/badge";
import { toast } from "sonner";

const rawBackendUrl = process.env.REACT_APP_BACKEND_URL?.trim();
const API_URL = rawBackendUrl || "";
const API_ROOT = API_URL ? `${API_URL}/api` : "/api";

function detectPlatform() {
  const ua = navigator.userAgent.toLowerCase();
  if (/android/.test(ua)) return "android";
  if (/iphone|ipad|ipod/.test(ua)) return "ios";
  if (/windows/.test(ua)) return "windows";
  if (/macintosh|mac os x/.test(ua)) return "macos";
  if (/linux/.test(ua)) return "linux";
  return "unknown";
}

const PLATFORM_CAPABILITIES = {
  windows: {
    available: ["EDR / Threat detection", "Process monitor", "Registry monitor", "File system monitor", "Network monitor", "Sigma rule detection", "USB device tracking", "Browser credential scan", "Persistence scan", "WebSocket live commands"],
    unavailable: ["Mobile threat defense", "MDM app policy", "IMEI / SIM management"],
  },
  linux: {
    available: ["EDR / Threat detection", "Process monitor", "File system monitor", "Network monitor", "Sigma rule detection", "eBPF kernel sensors", "USB device tracking", "WebSocket live commands"],
    unavailable: ["Registry monitor", "Mobile threat defense", "MDM app policy"],
  },
  macos: {
    available: ["EDR / Threat detection", "Process monitor", "File system monitor", "Network monitor", "Sigma rule detection", "Keychain monitor", "USB device tracking", "WebSocket live commands"],
    unavailable: ["Registry monitor", "Mobile threat defense", "MDM app policy"],
  },
  android: {
    available: ["MDM enrollment", "Mobile threat defense", "App analysis & policy", "VPN enforcement", "Device encryption check", "Jailbreak / root detection", "Network VPN"],
    unavailable: ["Process monitor", "Registry monitor", "File system monitor (sandboxed)", "WebSocket live commands"],
  },
  ios: {
    available: ["MDM enrollment", "VPN policy enforcement", "App management policy", "Device encryption (always on)", "Supervised mode features"],
    unavailable: ["Process monitor", "Registry monitor", "File system access", "WebSocket live commands", "Sideload APK"],
  },
  unknown: {
    available: ["Basic enrollment", "Heartbeat agent", "Network monitor"],
    unavailable: ["Platform-specific sensors (auto-detected at runtime)"],
  },
};

const PLATFORM_META = {
  windows: {
    label: "WINDOWS // FULL SENSOR STACK",
    summary: "Kernel, process, registry, credential, and network telemetry with remote command support.",
    accent: "#00f0ff",
  },
  linux: {
    label: "LINUX // EDR + eBPF",
    summary: "Cross-host process visibility, filesystem telemetry, network inspection, and eBPF-backed kernel sensing.",
    accent: "#39ff14",
  },
  macos: {
    label: "MACOS // WORKSTATION DEFENSE",
    summary: "Endpoint detection with filesystem, keychain, USB, and network visibility tuned for Apple hosts.",
    accent: "#ff2bd6",
  },
  android: {
    label: "ANDROID // MOBILE DEFENSE",
    summary: "MDM, VPN enforcement, mobile threat defense, and app policy deployment for field devices.",
    accent: "#ffb020",
  },
  ios: {
    label: "IOS // SUPERVISED CONTROL",
    summary: "Enrollment, supervised mode policy, VPN control, and device assurance workflows for managed fleets.",
    accent: "#7c3aed",
  },
  unknown: {
    label: "GENERIC // BASE ENROLLMENT",
    summary: "Fallback enrollment profile with baseline heartbeat and network visibility until the agent identifies the host.",
    accent: "#4cc4ff",
  },
};

function formatInstallLabel(platformKey) {
  const key = String(platformKey || "").toLowerCase();
  if (key === "android") return "Android APK";
  if (key === "ios") return "iOS Package";
  if (key === "macos") return "macOS Package";
  return `${key.toUpperCase()} Package`;
}

const PACKAGE_ICON = "/icon-transparent.png";

const PLATFORM_BADGE = {
  linux: { tone: "Penguin EDR", color: "#39ff14" },
  windows: { tone: "Win sensor stack", color: "#00f0ff" },
  macos: { tone: "Apple workstation", color: "#ff2bd6" },
  android: { tone: "Termux + APK", color: "#ffb020" },
  ios: { tone: "Pythonista / TestFlight", color: "#7c3aed" },
  docker: { tone: "Container drop-in", color: "#4cc4ff" },
};

function PackageIconBadge({ platformKey }) {
  const meta = PLATFORM_BADGE[platformKey] || { tone: "Generic agent", color: "#4cc4ff" };
  return (
    <div
      className="flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-xl border bg-slate-950/60"
      style={{ borderColor: `${meta.color}55`, boxShadow: `0 0 18px ${meta.color}33` }}
    >
      <img src={PACKAGE_ICON} alt="Seraph package icon" className="h-9 w-9 object-contain" />
    </div>
  );
}

function PlatformCapabilities({ platform }) {
  const caps = PLATFORM_CAPABILITIES[platform] || PLATFORM_CAPABILITIES.unknown;
  return (
    <Card className="seraph-hud-frame border-0 bg-transparent overflow-hidden">
      <CardHeader className="pb-3">
        <div className="flex items-center gap-3 mb-2">
          <span className="seraph-pip seraph-pip--green" />
          <span
            className="text-[10px] uppercase tracking-[0.34em]"
            style={{ color: "var(--neon-green)", fontFamily: "'JetBrains Mono', monospace" }}
          >
            Capability Matrix
          </span>
        </div>
        <CardTitle className="text-base md:text-lg text-slate-100">Platform Capabilities — {platform.toUpperCase()}</CardTitle>
        <CardDescription className="text-slate-400">What this device can monitor with the deployed agent package.</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="rounded-xl border border-emerald-400/20 bg-emerald-400/5 p-4">
            <p className="text-xs uppercase tracking-[0.28em] text-green-400 mb-3 font-semibold">Available</p>
            <ul className="space-y-1">
              {caps.available.map((cap) => (
                <li key={cap} className="flex items-center gap-2 text-sm text-slate-200">
                  <CheckCircle className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
                  {cap}
                </li>
              ))}
            </ul>
          </div>
          <div className="rounded-xl border border-fuchsia-400/25 bg-fuchsia-400/10 p-4">
            <p className="text-xs uppercase tracking-[0.28em] text-fuchsia-200 mb-3 font-semibold">Not Available</p>
            <ul className="space-y-1">
              {caps.unavailable.map((cap) => (
                <li key={cap} className="flex items-center gap-2 text-sm text-fuchsia-100/90">
                  <XCircle className="w-3.5 h-3.5 text-fuchsia-300 flex-shrink-0" />
                  {cap}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function EnrollmentPage() {
  const platform = useMemo(() => detectPlatform(), []);
  const platformMeta = PLATFORM_META[platform] || PLATFORM_META.unknown;
  const capabilities = PLATFORM_CAPABILITIES[platform] || PLATFORM_CAPABILITIES.unknown;
  const enrollmentUrl = "https://devious-viability-linked.ngrok-free.dev/enroll";
  const directAndroidApkUrl = `${API_ROOT}/unified/agent/download/android`;
  const enrollmentQrUrl = `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(enrollmentUrl)}&size=280x280&margin=12&bgcolor=020813&color=00f0ff`;
  const localDashboardUrl = useMemo(() => {
    const { protocol, hostname } = window.location;
    return `${protocol}//${hostname}:5000`;
  }, []);
  const [form, setForm] = useState({ name: "", email: "", device_label: "" });
  const [result, setResult] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    try {
      const response = await fetch(`${API_ROOT}/unified/enrollment/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...form, platform, device_label: form.device_label || `${platform} device` }),
      });
      const data = await response.json();
      if (!response.ok || !data.success) throw new Error(data.detail || data.error || "Enrollment failed");
      setResult(data);
      toast.success("Enrollment registered on the unified dashboard");
    } catch (error) {
      toast.error(error.message);
    } finally {
      setSubmitting(false);
    }
  };

  const install = result?.install || {};
  const selectedInstall = install[platform] || install.linux;
  const command = selectedInstall?.cmd || selectedInstall?.termux_cmd || "";
  const availablePackages = Object.entries(install).filter(
    ([, value]) =>
      value?.download_url || value?.apk_url || value?.cmd || value?.termux_cmd || value?.message
  );

  return (
    <div className="seraph-cyberpunk-shell min-h-screen overflow-x-hidden text-slate-100" data-testid="enrollment-page">
      <div className="seraph-cyber-grid" />
      <div className="seraph-aurora-bg" />
      <div className="seraph-scanline-overlay" />

      <div className="relative z-10 min-h-screen px-4 py-6 md:px-8 lg:px-10">
        <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 seraph-cyberpunk-main seraph-cyberpunk-content">
          <section className="seraph-hud-frame overflow-hidden px-6 py-6 md:px-8 md:py-8">
            <div className="grid gap-8 xl:grid-cols-[1.2fr_0.8fr] xl:items-center">
              <div className="min-w-0 space-y-6">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="seraph-chip">
                    <span className="seraph-pip" />
                    ENROLLMENT GATE
                  </span>
                  <Badge className="border border-cyan-400/30 bg-cyan-400/10 px-3 py-1 text-cyan-200">
                    {platform.toUpperCase()}
                  </Badge>
                  <Badge className="border border-fuchsia-400/25 bg-fuchsia-400/10 px-3 py-1 text-fuchsia-200">
                    PORT 3000 CONTROL PLANE
                  </Badge>
                </div>

                <div className="space-y-4">
                  <div className="flex items-center gap-4">
                    <div className="rounded-xl border border-cyan-400/30 bg-cyan-400/10 p-3 shadow-[0_0_24px_rgba(0,240,255,0.18)]">
                      <img
                        src="/icon-transparent.png"
                        alt="Seraph icon"
                        className="h-16 w-16 object-contain"
                      />
                    </div>
                    <div className="text-xs uppercase tracking-[0.32em] text-cyan-200" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                      Enrollment Signature // Seraph Iconography
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="seraph-pip" />
                    <span
                      className="text-[10px] uppercase tracking-[0.42em]"
                      style={{ color: "var(--neon-cyan)", fontFamily: "'JetBrains Mono', monospace" }}
                    >
                      Cyber Enrollment Interface
                    </span>
                  </div>
                  <h1
                    className="seraph-gradient-text seraph-fx-glitch-in text-4xl font-black uppercase leading-none md:text-6xl"
                    style={{ fontFamily: "'Orbitron', sans-serif" }}
                  >
                    Register Agent. Download Payload. Bring The Host Online.
                  </h1>
                  <p className="max-w-3xl text-base text-slate-300 md:text-lg">
                    This device is pre-registered with the unified command surface, then issued the correct installer, bootstrap command, and local dashboard link in one flow.
                  </p>
                </div>

                <div className="grid gap-4 sm:grid-cols-3">
                  <div className="seraph-stat-tile">
                    <p className="mb-2 text-[11px] uppercase tracking-[0.28em] text-slate-400">Target Profile</p>
                    <p className="text-lg font-semibold text-white">{platformMeta.label}</p>
                    <p className="mt-2 text-sm text-slate-400">{platformMeta.summary}</p>
                  </div>
                  <div className="seraph-stat-tile">
                    <p className="mb-2 text-[11px] uppercase tracking-[0.28em] text-slate-400">Capabilities Online</p>
                    <p className="text-4xl font-black text-cyan-300">{capabilities.available.length}</p>
                    <p className="mt-2 text-sm text-slate-400">Sensors and controls available immediately after installation.</p>
                  </div>
                  <div className="seraph-stat-tile">
                    <p className="mb-2 text-[11px] uppercase tracking-[0.28em] text-slate-400">Unavailable Paths</p>
                    <p className="text-4xl font-black text-fuchsia-300">{capabilities.unavailable.length}</p>
                    <p className="mt-2 text-sm text-slate-400">Platform restrictions surfaced before package delivery.</p>
                  </div>
                </div>
              </div>

              <div className="min-w-0 seraph-hud-frame bg-transparent p-5 md:p-6">
                <div className="mb-4 flex items-center gap-3">
                  <span className="seraph-pip seraph-pip--pink" />
                  <span className="text-[10px] uppercase tracking-[0.36em] text-fuchsia-200" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                    Flow Overview
                  </span>
                </div>
                <div className="space-y-4">
                  {[
                    "Identify the current host profile and expected monitor coverage.",
                    "Create the enrollment record in the unified backend control plane.",
                    "Return the install command, packages, and local dashboard address for this host.",
                  ].map((step, index) => (
                    <div key={step} className="flex gap-4 rounded-xl border border-cyan-400/15 bg-slate-950/40 p-4">
                      <div className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-full border border-cyan-400/40 bg-cyan-400/10 font-mono text-sm text-cyan-200">
                        0{index + 1}
                      </div>
                      <p className="text-sm leading-6 text-slate-300">{step}</p>
                    </div>
                  ))}
                </div>

                <div className="mt-5 rounded-xl border border-cyan-400/20 bg-cyan-400/5 p-4">
                  <div className="mb-2 flex items-center gap-2 text-cyan-200">
                    <Sparkles className="h-4 w-4" />
                    <span className="text-xs uppercase tracking-[0.24em]">Operator Note</span>
                  </div>
                  <p className="text-sm text-slate-300">
                    Enrollment events appear on the port 3000 unified dashboard, while the downloaded agent exposes its own local cyber dashboard on port 5000.
                  </p>
                </div>
              </div>
            </div>
          </section>

          <section className="grid gap-6 xl:grid-cols-[0.92fr_1.08fr]">
            {!result ? (
              <Card className="seraph-hud-frame border-0 bg-transparent overflow-hidden">
                <CardHeader className="pb-2">
                  <div className="mb-3 flex items-center gap-3">
                    <span className="seraph-pip" />
                    <span className="text-[10px] uppercase tracking-[0.36em] text-cyan-200" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                      Registration Payload
                    </span>
                  </div>
                  <CardTitle className="flex items-center gap-2 text-xl text-white">
                    <MonitorSmartphone className="h-5 w-5 text-cyan-300" />
                    Device Details
                  </CardTitle>
                  <CardDescription className="text-slate-400">Create the enrollment record and issue the platform-matched installer sequence.</CardDescription>
                </CardHeader>
                <CardContent>
                  <form onSubmit={submit} className="space-y-4">
                    <div className="space-y-2">
                      <label className="text-[10px] uppercase tracking-[0.34em] text-cyan-200" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                        Operator Name
                      </label>
                      <Input className="seraph-input h-12" placeholder="Guardian name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
                    </div>
                    <div className="space-y-2">
                      <label className="text-[10px] uppercase tracking-[0.34em] text-cyan-200" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                        Contact Channel
                      </label>
                      <Input className="seraph-input h-12" placeholder="operator@domain.tld" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required />
                    </div>
                    <div className="space-y-2">
                      <label className="text-[10px] uppercase tracking-[0.34em] text-cyan-200" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                        Host Label
                      </label>
                      <Input className="seraph-input h-12" placeholder={`${platform} edge node`} value={form.device_label} onChange={(e) => setForm({ ...form, device_label: e.target.value })} />
                    </div>

                    <div className="rounded-xl border border-fuchsia-400/15 bg-fuchsia-400/5 p-4 text-sm text-slate-300">
                      <div className="mb-2 flex items-center gap-2 text-fuchsia-200">
                        <span className="seraph-pip seraph-pip--pink" />
                        <span className="text-[10px] uppercase tracking-[0.3em]" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                          Routing Target
                        </span>
                      </div>
                      This request is posted to the unified backend enrollment API and mirrored into the agent operations dashboard for command tracking.
                    </div>

                    <div className="rounded-xl border border-cyan-400/20 bg-cyan-400/8 p-4 text-sm text-slate-300">
                      <div className="mb-2 flex items-center gap-2 text-cyan-200">
                        <Download className="h-4 w-4" />
                        <span className="text-[10px] uppercase tracking-[0.3em]" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                          Direct Android Package
                        </span>
                      </div>
                      <p className="mb-3 text-slate-300">Need the APK now? Grab the latest Android agent package directly.</p>
                      <Button
                        type="button"
                        className="seraph-btn seraph-btn-primary border-0 px-5 py-3"
                        onClick={() => window.open(directAndroidApkUrl, "_blank", "noopener,noreferrer")}
                      >
                        <Download className="mr-2 h-4 w-4" /> Download Android APK
                      </Button>
                    </div>

                    <Button disabled={submitting} className="seraph-btn seraph-btn-primary h-12 w-full border-0 text-sm">
                      <ShieldCheck className="mr-2 h-4 w-4" />
                      {submitting ? "Registering Device" : "Register Device"}
                      <ArrowRight className="ml-2 h-4 w-4" />
                    </Button>
                  </form>
                </CardContent>
              </Card>
            ) : (
              <Card className="seraph-hud-frame border-0 bg-transparent overflow-hidden">
                <CardHeader className="pb-2">
                  <div className="mb-3 flex items-center gap-3">
                    <span className="seraph-pip seraph-pip--green" />
                    <span className="text-[10px] uppercase tracking-[0.36em] text-green-300" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                      Installer Issued
                    </span>
                  </div>
                  <CardTitle className="text-xl text-white">Installer Ready</CardTitle>
                  <CardDescription className="text-slate-400">Device ID: {result.device_id}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-5">
                  {command && (
                    <div className="rounded-2xl border border-cyan-400/20 bg-slate-950/70 p-4">
                      <div className="mb-3 flex items-center justify-between gap-3">
                        <span className="flex items-center gap-2 text-sm text-slate-200">
                          <Terminal className="h-4 w-4 text-cyan-300" />
                          Install Command
                        </span>
                        <Button size="sm" className="seraph-btn border-0 px-3 py-2 text-[11px]" onClick={() => navigator.clipboard.writeText(command)}>
                          <Copy className="mr-1 h-3 w-3" /> Copy
                        </Button>
                      </div>
                      <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-xl border border-cyan-400/10 bg-black/40 p-3 text-xs text-cyan-200">{command}</pre>
                    </div>
                  )}

                  <div className="grid gap-3 md:grid-cols-2">
                    {availablePackages.map(([key, value]) => {
                      const url = value?.download_url || value?.apk_url;
                      const badge = PLATFORM_BADGE[key] || PLATFORM_BADGE.docker;
                      const requirements = Array.isArray(value?.requirements) ? value.requirements : [];
                      return (
                        <button
                          key={key}
                          type="button"
                          onClick={() => url && window.open(url, "_blank", "noopener,noreferrer")}
                          className="seraph-stat-tile text-left"
                          disabled={!url}
                          style={{ opacity: url ? 1 : 0.7 }}
                        >
                          <div className="flex items-start gap-3">
                            <PackageIconBadge platformKey={key} />
                            <div className="flex-1 min-w-0">
                              <p className="text-[10px] uppercase tracking-[0.28em]" style={{ color: badge.color }}>
                                {badge.tone}
                              </p>
                              <p className="mt-1 text-lg font-semibold text-white">{formatInstallLabel(key)}</p>
                              {url ? (
                                <p className="mt-2 flex items-center gap-2 text-sm text-cyan-200">
                                  Download package
                                  <Download className="h-4 w-4" />
                                </p>
                              ) : (
                                <p className="mt-2 text-xs text-slate-400">
                                  {value?.message || "Use the install command for this host."}
                                </p>
                              )}
                            </div>
                          </div>
                          {requirements.length > 0 && (
                            <ul className="mt-3 space-y-1 border-t border-cyan-400/10 pt-2">
                              {requirements.map((req) => (
                                <li key={req} className="text-[11px] text-slate-300">
                                  <span className="mr-2 text-cyan-300">&#9656;</span>
                                  {req}
                                </li>
                              ))}
                            </ul>
                          )}
                        </button>
                      );
                    })}
                  </div>

                  <div className="flex flex-wrap gap-3">
                    {selectedInstall?.download_url && (
                      <Button className="seraph-btn seraph-btn-primary border-0 px-5 py-3" onClick={() => window.open(selectedInstall.download_url, "_blank", "noopener,noreferrer")}>
                        <Download className="mr-2 h-4 w-4" /> Download Package
                      </Button>
                    )}
                    {install.android?.apk_url && !selectedInstall?.download_url && (
                      <Button className="seraph-btn seraph-btn-primary border-0 px-5 py-3" onClick={() => window.open(install.android.apk_url, "_blank", "noopener,noreferrer")}>
                        <Download className="mr-2 h-4 w-4" /> Android APK
                      </Button>
                    )}
                    <Button className="seraph-btn border-0 px-5 py-3" onClick={() => window.open(localDashboardUrl, "_blank", "noopener,noreferrer")}>
                      Open Local Dashboard
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )}

            <div className="space-y-6">
              <Card className="seraph-hud-frame border-0 bg-transparent overflow-hidden">
                <CardHeader className="pb-2">
                  <div className="mb-3 flex items-center gap-3">
                    <span className="seraph-pip seraph-pip--amber" />
                    <span className="text-[10px] uppercase tracking-[0.36em] text-amber-200" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                      Live Enrollment QR
                    </span>
                  </div>
                  <CardTitle className="text-lg text-white">Scan To Open Enrollment</CardTitle>
                  <CardDescription className="text-slate-400 break-all">{enrollmentUrl}</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-col items-center gap-4 rounded-xl border border-cyan-400/20 bg-slate-950/50 p-4">
                    <img
                      src={enrollmentQrUrl}
                      alt="QR code linking to enrollment page"
                      className="h-52 w-52 rounded-lg border border-cyan-400/30 bg-slate-950 p-2 shadow-[0_0_24px_rgba(0,240,255,0.18)]"
                    />
                    <Button
                      type="button"
                      className="seraph-btn border-0 px-5 py-3"
                      onClick={() => window.open(enrollmentUrl, "_blank", "noopener,noreferrer")}
                    >
                      Open Enrollment URL
                    </Button>
                  </div>
                </CardContent>
              </Card>

              <PlatformCapabilities platform={platform} />

              <Card className="seraph-hud-frame border-0 bg-transparent overflow-hidden">
                <CardHeader className="pb-2">
                  <div className="mb-3 flex items-center gap-3">
                    <span className="seraph-pip seraph-pip--amber" />
                    <span className="text-[10px] uppercase tracking-[0.36em] text-amber-200" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                      Delivery Output
                    </span>
                  </div>
                  <CardTitle className="text-lg text-white">Post-Enrollment Outcomes</CardTitle>
                  <CardDescription className="text-slate-400">What the operator receives after registration completes.</CardDescription>
                </CardHeader>
                <CardContent className="grid gap-3">
                  {[
                    "Unified device identifier for command and audit trails.",
                    "Host-specific install command or mobile package URL.",
                    "Direct handoff into the local dashboard running on port 5000.",
                  ].map((item) => (
                    <div key={item} className="flex items-start gap-3 rounded-xl border border-cyan-400/10 bg-slate-950/40 p-4">
                      <CheckCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-cyan-300" />
                      <p className="text-sm text-slate-300">{item}</p>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
