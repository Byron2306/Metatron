import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { toast } from "sonner";
import {
  Chrome,
  Download,
  Shield,
  Zap,
  Fingerprint,
  Eye,
  Lock,
  CheckCircle2,
  AlertTriangle
} from "lucide-react";

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || "").trim();
const API_URL = !envBackendUrl || envBackendUrl === "undefined" || envBackendUrl === "null"
  ? ""
  : envBackendUrl.replace(/\/+$/, "");

const FEATURES = [
  {
    icon: Shield,
    title: "Real-time Threat Detection",
    description: "Watches live page behavior for malicious scripts and suspicious navigation patterns."
  },
  {
    icon: Fingerprint,
    title: "Anti-Fingerprinting Guard",
    description: "Flags high-risk script behavior linked to tracking and identity leakage."
  },
  {
    icon: Eye,
    title: "Active Session Protection",
    description: "Monitors sensitive browser events tied to session theft and exfil attempts."
  },
  {
    icon: Lock,
    title: "Domain Enforcement",
    description: "Checks suspicious destinations against backend intelligence and blocks high-risk pivots."
  }
];

const EXTENSION_BEHAVIORS = [
  "Intercepts top-level browser navigation events and validates target domains through the backend threat intelligence API.",
  "Scans newly injected script blocks in active pages for suspicious runtime patterns linked to obfuscation and credential theft.",
  "Queues detections locally and batches telemetry to the backend so short outages do not lose events.",
  "Displays quick protection state and event counters directly from local extension storage in the popup UI."
];

const INSTALL_STEPS = [
  "Click Download Extension ZIP, then extract the archive into a dedicated folder.",
  "Open chrome://extensions or edge://extensions and turn on Developer mode.",
  "Click Load unpacked and select the extracted extension folder.",
  "Pin the extension icon, open it once, and confirm the status panel shows protection active.",
  "Browse to a known test domain or trigger a safe detection test to verify telemetry flow."
];

const INCLUDED_FILES = [
  "manifest.json (permissions and extension wiring)",
  "background.js (navigation checks and alert queue)",
  "content.js (live DOM/script behavior monitoring)",
  "popup.html + popup.js (operator status panel)",
  "blocked.html (interstitial shown for blocked malicious domains)",
  "icons/* (toolbar and extension identity assets)"
];

export default function BrowserExtensionPage() {
  const downloadExtension = () => {
    window.open(`${API_URL}/api/extension/download`, "_blank");
    toast.success("Seraph extension package download started");
  };

  return (
    <div className="space-y-6 p-6" data-testid="browser-extension-page">
      <div className="rounded-2xl border border-cyan-400/30 bg-[radial-gradient(circle_at_top_left,rgba(0,240,255,0.2),transparent_45%),linear-gradient(135deg,rgba(8,19,34,0.95),rgba(13,33,59,0.95))] p-6 shadow-[0_0_48px_rgba(0,240,255,0.15)]">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <div className="rounded-xl border border-cyan-400/30 bg-cyan-400/10 p-2">
                <img src="/icon-transparent.png" alt="Seraph" className="h-10 w-10 object-contain" />
              </div>
              <Badge className="border border-cyan-400/50 bg-cyan-400/15 text-cyan-200">
                Cyberpunk Release
              </Badge>
            </div>
            <h1 className="flex items-center gap-2 text-3xl font-bold text-white">
              <Chrome className="h-7 w-7 text-cyan-300" />
              Browser Extension Package
            </h1>
            <p className="max-w-2xl text-sm text-cyan-100/80">
              One click, fully packaged ZIP. No tab-by-tab copy/paste. Download and load the extension directly in Chrome, Edge, or Brave.
            </p>
          </div>

          <Button
            onClick={downloadExtension}
            className="h-12 border border-cyan-300/40 bg-cyan-500/20 px-6 text-cyan-100 shadow-[0_0_28px_rgba(0,240,255,0.3)] hover:bg-cyan-500/30"
            data-testid="download-extension-btn"
          >
            <Download className="mr-2 h-4 w-4" />
            Download Extension ZIP
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        {FEATURES.map((feature, index) => (
          <Card
            key={feature.title}
            className="border-cyan-900/60 bg-slate-950/70 backdrop-blur"
            data-testid={`feature-card-${index}`}
          >
            <CardContent className="pt-6">
              <div className="mb-3 inline-flex rounded-lg border border-cyan-400/30 bg-cyan-500/10 p-2">
                <feature.icon className="h-5 w-5 text-cyan-300" />
              </div>
              <h3 className="text-sm font-semibold text-white">{feature.title}</h3>
              <p className="mt-1 text-xs text-slate-300">{feature.description}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card className="border-cyan-900/60 bg-slate-950/70">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-white">
            <Zap className="h-5 w-5 text-cyan-300" />
            Install Instructions
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-slate-200">
          {INSTALL_STEPS.map((step, idx) => (
            <div key={step} className="flex items-start gap-2">
              <CheckCircle2 className="mt-0.5 h-4 w-4 text-cyan-300" />
              <p>
                <span className="mr-2 font-semibold text-cyan-200">{idx + 1}.</span>
                {step}
              </p>
            </div>
          ))}

          <div className="mt-4 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3">
            <div className="flex items-start gap-2">
              <AlertTriangle className="mt-0.5 h-4 w-4 text-amber-300" />
              <p className="text-xs text-amber-100">
                If your backend runs on a non-default host or port, update extension network policy in your deployment before production rollout.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <Card className="border-cyan-900/60 bg-slate-950/70">
          <CardHeader>
            <CardTitle className="text-white">What The Extension Does</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm text-slate-200">
            {EXTENSION_BEHAVIORS.map((line) => (
              <div key={line} className="flex items-start gap-2">
                <Shield className="mt-0.5 h-4 w-4 text-cyan-300" />
                <p>{line}</p>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card className="border-cyan-900/60 bg-slate-950/70">
          <CardHeader>
            <CardTitle className="text-white">What Is Included In The ZIP</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm text-slate-200">
            {INCLUDED_FILES.map((item) => (
              <div key={item} className="flex items-start gap-2">
                <CheckCircle2 className="mt-0.5 h-4 w-4 text-cyan-300" />
                <p>{item}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}