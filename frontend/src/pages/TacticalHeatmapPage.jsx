import { useState, useEffect, useRef } from "react";
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select";
import { useAuth } from "../context/AuthContext";
import { toast } from "sonner";
import SeraphPageHeader from "../components/SeraphPageHeader";
import {
  Activity,
  AlertTriangle,
  Shield,
  RefreshCw,
  Filter,
  Maximize2,
  Download,
  ZoomIn,
  ZoomOut,
  Map
} from "lucide-react";

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API_URL = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? ''
  : envBackendUrl.replace(/\/+$/, '');

export default function TacticalHeatmapPage() {
  const { token } = useAuth();
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState("24h");
  const [filterSeverity, setFilterSeverity] = useState("all");
  const [heatmapData, setHeatmapData] = useState([]);
  const canvasRef = useRef(null);
  const [stats, setStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  });

  useEffect(() => {
    fetchThreats();
    const interval = setInterval(fetchThreats, 30000);
    return () => clearInterval(interval);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [timeRange, filterSeverity]);

  useEffect(() => {
    if (heatmapData.length > 0) {
      drawHeatmap();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [heatmapData]);

  const fetchThreats = async () => {
    try {
      const response = await fetch(`${API_URL}/api/threats?limit=200`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json();
      
      // Process threats for heatmap
      const processedThreats = (data.threats || data || []).map(t => ({
        ...t,
        x: Math.random() * 100,
        y: Math.random() * 100,
        intensity: getSeverityIntensity(t.severity)
      }));
      
      setThreats(processedThreats);
      calculateStats(processedThreats);
      processHeatmapData(processedThreats);
    } catch (error) {
      toast.error("Failed to fetch threat data");
    } finally {
      setLoading(false);
    }
  };

  const getSeverityIntensity = (severity) => {
    const map = { critical: 1.0, high: 0.75, medium: 0.5, low: 0.25 };
    return map[severity?.toLowerCase()] || 0.3;
  };

  const calculateStats = (threatList) => {
    const stats = {
      total: threatList.length,
      critical: threatList.filter(t => t.severity === "critical").length,
      high: threatList.filter(t => t.severity === "high").length,
      medium: threatList.filter(t => t.severity === "medium").length,
      low: threatList.filter(t => t.severity === "low").length
    };
    setStats(stats);
  };

  const processHeatmapData = (threatList) => {
    // Group threats by type and severity for heatmap visualization
    const typeGroups = {};
    
    threatList.forEach(threat => {
      const type = threat.type || "unknown";
      if (!typeGroups[type]) {
        typeGroups[type] = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
      }
      typeGroups[type][threat.severity || "low"]++;
      typeGroups[type].total++;
    });
    
    // Convert to array for visualization
    const heatData = Object.entries(typeGroups).map(([type, counts], index) => ({
      type,
      ...counts,
      x: (index % 5) * 20 + 10,
      y: Math.floor(index / 5) * 20 + 10,
      intensity: (counts.critical * 4 + counts.high * 3 + counts.medium * 2 + counts.low) / (counts.total * 4)
    }));
    
    setHeatmapData(heatData);
  };

  const drawHeatmap = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    const width = canvas.width;
    const height = canvas.height;
    const t = Date.now() / 1000;

    // Deep space gradient background
    const bg = ctx.createRadialGradient(width / 2, height / 2, 0, width / 2, height / 2, Math.max(width, height) / 1.2);
    bg.addColorStop(0, "rgba(7, 16, 28, 1)");
    bg.addColorStop(0.6, "rgba(2, 8, 19, 1)");
    bg.addColorStop(1, "rgba(0, 0, 4, 1)");
    ctx.fillStyle = bg;
    ctx.fillRect(0, 0, width, height);

    // Subtle aurora glow zones
    const aurora1 = ctx.createRadialGradient(width * 0.18, height * 0.22, 0, width * 0.18, height * 0.22, width * 0.5);
    aurora1.addColorStop(0, "rgba(0, 240, 255, 0.10)");
    aurora1.addColorStop(1, "rgba(0, 240, 255, 0)");
    ctx.fillStyle = aurora1;
    ctx.fillRect(0, 0, width, height);

    const aurora2 = ctx.createRadialGradient(width * 0.84, height * 0.78, 0, width * 0.84, height * 0.78, width * 0.5);
    aurora2.addColorStop(0, "rgba(188, 19, 254, 0.10)");
    aurora2.addColorStop(1, "rgba(188, 19, 254, 0)");
    ctx.fillStyle = aurora2;
    ctx.fillRect(0, 0, width, height);

    // Cyan grid
    ctx.strokeStyle = "rgba(0, 240, 255, 0.07)";
    ctx.lineWidth = 1;
    const cell = 40;
    for (let x = 0; x <= width; x += cell) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }
    for (let y = 0; y <= height; y += cell) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }

    // Animated scanline
    const scanY = ((t * 80) % height) | 0;
    const scanGrad = ctx.createLinearGradient(0, scanY - 60, 0, scanY + 60);
    scanGrad.addColorStop(0, "rgba(0, 240, 255, 0)");
    scanGrad.addColorStop(0.5, "rgba(0, 240, 255, 0.18)");
    scanGrad.addColorStop(1, "rgba(0, 240, 255, 0)");
    ctx.fillStyle = scanGrad;
    ctx.fillRect(0, scanY - 60, width, 120);

    // Heat spots — neon palette by intensity
    heatmapData.forEach((data, idx) => {
      const x = (data.x / 100) * width;
      const y = (data.y / 100) * height;
      const baseRadius = Math.max(34, data.total * 5);
      const pulse = 1 + Math.sin(t * 2 + idx) * 0.08;
      const radius = baseRadius * pulse;

      let core, mid;
      if (data.intensity > 0.7) {
        core = "#ff3838"; mid = "rgba(255, 56, 56,";
      } else if (data.intensity > 0.4) {
        core = "#ffb020"; mid = "rgba(255, 176, 32,";
      } else {
        core = "#39ff14"; mid = "rgba(57, 255, 20,";
      }

      // Outer halo
      const halo = ctx.createRadialGradient(x, y, 0, x, y, radius);
      halo.addColorStop(0, `${mid}0.85)`);
      halo.addColorStop(0.5, `${mid}0.32)`);
      halo.addColorStop(1, `${mid}0)`);
      ctx.fillStyle = halo;
      ctx.beginPath();
      ctx.arc(x, y, radius, 0, Math.PI * 2);
      ctx.fill();

      // Inner ring
      ctx.strokeStyle = core;
      ctx.shadowColor = core;
      ctx.shadowBlur = 14;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.arc(x, y, radius * 0.55, 0, Math.PI * 2);
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Bright core dot
      ctx.fillStyle = core;
      ctx.shadowColor = core;
      ctx.shadowBlur = 16;
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;

      // Label
      ctx.fillStyle = "#e6fbff";
      ctx.font = "bold 11px 'JetBrains Mono', monospace";
      ctx.textAlign = "center";
      ctx.shadowColor = core;
      ctx.shadowBlur = 4;
      ctx.fillText((data.type || "threat").toUpperCase().slice(0, 18), x, y + radius + 14);
      ctx.fillText(`◆ ${data.total}`, x, y + radius + 28);
      ctx.shadowBlur = 0;
    });

    // Legend
    ctx.font = "10px 'JetBrains Mono', monospace";
    ctx.textAlign = "left";
    ctx.fillStyle = "#9ed3e6";
    ctx.fillText("THREAT · INTENSITY", 14, height - 44);

    [
      { color: "#39ff14", label: "LOW" },
      { color: "#ffb020", label: "MEDIUM" },
      { color: "#ff3838", label: "HIGH / CRITICAL" }
    ].forEach((item, i) => {
      ctx.fillStyle = item.color;
      ctx.shadowColor = item.color;
      ctx.shadowBlur = 8;
      ctx.beginPath();
      ctx.arc(20 + i * 110, height - 24, 5, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;
      ctx.fillStyle = "#aef0ff";
      ctx.fillText(item.label, 32 + i * 110, height - 20);
    });

    // Continue animating while mounted
    if (canvasRef.current === canvas) {
      requestAnimationFrame(() => drawHeatmap());
    }
  };

  const exportHeatmap = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const link = document.createElement("a");
    link.download = `seraph-heatmap-${new Date().toISOString().split("T")[0]}.png`;
    link.href = canvas.toDataURL("image/png");
    link.click();
    toast.success("Heatmap exported");
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-cyan-400 animate-pulse">Loading Tactical Heatmap...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6 lg:p-8" data-testid="tactical-heatmap-page" data-accent="green">
      <SeraphPageHeader
        eyebrow="seraph · threats · tactical heatmap"
        title="Tactical Threat Heatmap"
        tagline="> AI-prioritized threat visualization · severity distribution · live export"
        accent="green"
        status={`${stats.total} SIGNALS`}
        actions={
          <div className="flex gap-2 flex-wrap justify-end">
          <Select value={timeRange} onValueChange={setTimeRange}>
            <SelectTrigger className="w-32 bg-slate-800 border-slate-700">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="1h">Last Hour</SelectItem>
              <SelectItem value="24h">Last 24h</SelectItem>
              <SelectItem value="7d">Last 7 Days</SelectItem>
              <SelectItem value="30d">Last 30 Days</SelectItem>
            </SelectContent>
          </Select>
          <Select value={filterSeverity} onValueChange={setFilterSeverity}>
            <SelectTrigger className="w-32 bg-slate-800 border-slate-700">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severity</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>
          <Button onClick={fetchThreats} variant="outline" size="icon">
            <RefreshCw className="w-4 h-4" />
          </Button>
          <Button onClick={exportHeatmap} variant="outline" size="icon">
            <Download className="w-4 h-4" />
          </Button>
          </div>
        }
      />

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <Card className="bg-slate-900/50 border-slate-800" data-testid="stat-total">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Total Threats</p>
                <p className="text-2xl font-bold text-white">{stats.total}</p>
              </div>
              <Shield className="w-8 h-8 text-cyan-500" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-slate-900/50 border-red-900/50" data-testid="stat-critical">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Critical</p>
                <p className="text-2xl font-bold text-red-500">{stats.critical}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-500" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-slate-900/50 border-orange-900/50" data-testid="stat-high">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">High</p>
                <p className="text-2xl font-bold text-orange-500">{stats.high}</p>
              </div>
              <Activity className="w-8 h-8 text-orange-500" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-slate-900/50 border-yellow-900/50" data-testid="stat-medium">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Medium</p>
                <p className="text-2xl font-bold text-yellow-500">{stats.medium}</p>
              </div>
              <Activity className="w-8 h-8 text-yellow-500" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-slate-900/50 border-green-900/50" data-testid="stat-low">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Low</p>
                <p className="text-2xl font-bold text-green-500">{stats.low}</p>
              </div>
              <Activity className="w-8 h-8 text-green-500" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Heatmap Canvas */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white">Threat Distribution Heatmap</CardTitle>
          <CardDescription>Visual representation of threat concentration by type</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="relative">
            <canvas
              ref={canvasRef}
              width={800}
              height={500}
              className="w-full rounded-lg border border-slate-700"
              style={{ maxHeight: "500px" }}
              data-testid="heatmap-canvas"
            />
          </div>
        </CardContent>
      </Card>

      {/* Threat Type Breakdown */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white">Threat Type Analysis</CardTitle>
          <CardDescription>Breakdown by threat category</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {heatmapData.map((data) => (
              <div
                key={data.type}
                className="p-4 bg-slate-800/50 rounded-lg border border-slate-700"
              >
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-medium text-white">{data.type.replace(/_/g, " ")}</h3>
                  <Badge variant={data.intensity > 0.7 ? "destructive" : data.intensity > 0.4 ? "secondary" : "outline"}>
                    {data.total}
                  </Badge>
                </div>
                <div className="space-y-1">
                  <div className="flex justify-between text-sm">
                    <span className="text-red-400">Critical</span>
                    <span className="text-white">{data.critical}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-orange-400">High</span>
                    <span className="text-white">{data.high}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-yellow-400">Medium</span>
                    <span className="text-white">{data.medium}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-green-400">Low</span>
                    <span className="text-white">{data.low}</span>
                  </div>
                </div>
                {/* Intensity bar */}
                <div className="mt-3 h-2 bg-slate-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${
                      data.intensity > 0.7 ? "bg-red-500" : data.intensity > 0.4 ? "bg-orange-500" : "bg-green-500"
                    }`}
                    style={{ width: `${data.intensity * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
