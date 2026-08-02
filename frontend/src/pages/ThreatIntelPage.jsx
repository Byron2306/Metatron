import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Database, Search, RefreshCw, AlertTriangle,
  Globe, Hash, Link as LinkIcon, CheckCircle, XCircle,
  TrendingUp, Clock, Activity
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Input } from '../components/ui/input';
import { toast } from 'sonner';
import SeraphPageHeader from '../components/SeraphPageHeader';

const envBackendUrl = (process.env.REACT_APP_BACKEND_URL || '').trim();
const API = !envBackendUrl || envBackendUrl === 'undefined' || envBackendUrl === 'null'
  ? '/api'
  : `${envBackendUrl.replace(/\/+$/, '')}/api`;

const SOPHIA_INTEL_NEON = {
  cyan: {
    borderClass: 'sophia-border-cyan',
    color: '#00f0ff',
    text: '#b9fbff',
    glow: 'rgba(0,240,255,0.62)',
    bg: 'rgba(0,240,255,0.09)',
    iconBg: 'rgba(0,240,255,0.18)',
    alt: '#ff2bd6',
  },
  magenta: {
    borderClass: 'sophia-border-magenta',
    color: '#ff2bd6',
    text: '#ffd1f8',
    glow: 'rgba(255,43,214,0.62)',
    bg: 'rgba(255,43,214,0.1)',
    iconBg: 'rgba(255,43,214,0.18)',
    alt: '#00f0ff',
  },
  green: {
    borderClass: 'sophia-border-green',
    color: '#39ff14',
    text: '#c9ffd5',
    glow: 'rgba(57,255,20,0.58)',
    bg: 'rgba(57,255,20,0.08)',
    iconBg: 'rgba(57,255,20,0.16)',
    alt: '#bc13fe',
  },
  purple: {
    borderClass: 'sophia-border-purple',
    color: '#bc13fe',
    text: '#efddff',
    glow: 'rgba(188,19,254,0.6)',
    bg: 'rgba(188,19,254,0.09)',
    iconBg: 'rgba(188,19,254,0.18)',
    alt: '#39ff14',
  },
};

function SophiaIntelPanel({ tone = 'cyan', className = '', style, children }) {
  const t = SOPHIA_INTEL_NEON[tone] || SOPHIA_INTEL_NEON.cyan;
  return (
    <div
      className={`sophia-ti-panel sophia-edge-sweep sophia-panel-glow ${t.borderClass} ${className}`}
      style={{
        '--sophia-hud-color': t.color,
        '--sophia-hud-color-alt': t.alt,
        '--sophia-ti-glow': t.glow,
        '--sophia-ti-bg': t.bg,
        ...style,
      }}
    >
      <span className="sophia-ti-scanlines" />
      {children}
    </div>
  );
}

const ThreatIntelPage = () => {
  const { token } = useAuth();
  const [stats, setStats] = useState(null);
  const [searchValue, setSearchValue] = useState('');
  const [searchResult, setSearchResult] = useState(null);
  const [recentMatches, setRecentMatches] = useState([]);
  const [loading, setLoading] = useState(false);
  const [updating, setUpdating] = useState(false);

  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    fetchStats();
    fetchRecentMatches();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  const fetchStats = async () => {
    try {
      const res = await axios.get(`${API}/threat-intel/stats`, { headers });
      setStats(res.data);
    } catch (err) {
      toast.error('Failed to fetch threat intel stats');
    }
  };

  const fetchRecentMatches = async () => {
    try {
      const res = await axios.get(`${API}/threat-intel/matches/recent?limit=20`, { headers });
      setRecentMatches(res.data);
    } catch (err) {
      console.error('Failed to fetch recent matches');
    }
  };

  const handleSearch = async () => {
    if (!searchValue.trim()) return;
    setLoading(true);
    try {
      const res = await axios.post(`${API}/threat-intel/check`, 
        { value: searchValue.trim() }, 
        { headers }
      );
      setSearchResult(res.data);
      if (res.data.matched) {
        toast.warning('Threat indicator matched!');
      } else {
        toast.success('No threats found');
      }
    } catch (err) {
      toast.error('Search failed');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateFeeds = async () => {
    setUpdating(true);
    try {
      const res = await axios.post(`${API}/threat-intel/update`, {}, { headers });
      toast.success(`Feeds updated: ${res.data.stats?.total_indicators || 0} indicators`);
      fetchStats();
    } catch (err) {
      toast.error('Failed to update feeds');
    } finally {
      setUpdating(false);
    }
  };

  const getTypeIcon = (type) => {
    switch(type) {
      case 'ip': return <Globe className="w-4 h-4" />;
      case 'domain': return <Globe className="w-4 h-4" />;
      case 'url': return <LinkIcon className="w-4 h-4" />;
      case 'md5': case 'sha1': case 'sha256': return <Hash className="w-4 h-4" />;
      default: return <Database className="w-4 h-4" />;
    }
  };

  const statTiles = [
    { label: 'Total Indicators', value: stats?.total_indicators?.toLocaleString() || 0, icon: Database, tone: 'cyan' },
    { label: 'Active Feeds', value: stats?.enabled_feeds?.length || 0, icon: Activity, tone: 'green' },
    { label: 'IP Indicators', value: stats?.by_type?.ip?.toLocaleString() || 0, icon: Globe, tone: 'magenta' },
    { label: 'URL Indicators', value: stats?.by_type?.url?.toLocaleString() || 0, icon: LinkIcon, tone: 'purple' },
  ];

  return (
    <div className="space-y-6 p-6 lg:p-8 sophia-no-glitch" data-testid="threat-intel-page" data-sophia-glitch="false" data-accent="magenta">
      <SeraphPageHeader
        eyebrow="seraph · threat-intel · indicator lattice"
        title="Threat Intelligence"
        tagline="> real-time IOC lookup · feed health · indicator confidence"
        accent="pink"
        status={updating ? 'UPDATING' : 'FEEDS LIVE'}
        actions={
          <Button
            onClick={handleUpdateFeeds}
            disabled={updating}
            variant="outline"
            className="sophia-btn sophia-btn-refresh sophia-ti-button"
            data-testid="update-feeds-btn"
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${updating ? 'animate-spin' : ''}`} />
            {updating ? 'Updating...' : 'Update Feeds'}
          </Button>
        }
      />

      {/* Stats */}
      <div className="seraph-stat-grid grid grid-cols-1 md:grid-cols-4 gap-4">
        {statTiles.map(({ label, value, icon: Icon, tone }, index) => {
          const t = SOPHIA_INTEL_NEON[tone];
          return (
            <motion.div key={label} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * 0.1 }}>
              <SophiaIntelPanel tone={tone} className="seraph-stat-tile p-4 min-h-[8.25rem]">
                <div className="flex items-center gap-3">
                  <div
                    className="w-12 h-12 flex items-center justify-center"
                    style={{
                      background: `linear-gradient(135deg, ${t.iconBg}, rgba(2,8,19,0.82))`,
                      border: `1px solid ${t.color}`,
                      boxShadow: `0 0 14px ${t.glow}, inset 0 0 10px ${t.bg}`,
                      clipPath: 'polygon(8px 0,100% 0,100% calc(100% - 8px),calc(100% - 8px) 100%,0 100%,0 8px)',
                    }}
                  >
                    <Icon className="w-6 h-6" style={{ color: t.color, filter: `drop-shadow(0 0 8px ${t.glow})` }} />
                  </div>
                  <div>
                    <p className="sophia-scan sophia-terminal-label text-sm" style={{ color: t.text }}>{label}</p>
                    <p
                      className="sophia-flicker sophia-terminal-value text-3xl font-bold"
                      style={{ color: t.color, textShadow: `0 0 18px ${t.glow}, 0 0 42px ${t.glow}` }}
                    >
                      {value}
                    </p>
                  </div>
                </div>
              </SophiaIntelPanel>
            </motion.div>
          );
        })}
      </div>

      {/* IOC Search */}
      <SophiaIntelPanel tone="magenta" className="p-5">
        <div className="mb-4 flex items-center gap-2">
          <Search className="w-5 h-5" style={{ color: SOPHIA_INTEL_NEON.magenta.color, filter: `drop-shadow(0 0 8px ${SOPHIA_INTEL_NEON.magenta.glow})` }} />
          <h2 className="sophia-scan sophia-terminal-heading text-base">
            IOC Lookup
          </h2>
        </div>
        <div className="flex flex-col gap-3 md:flex-row">
          <Input
            placeholder="Enter IP, domain, URL, or file hash..."
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            className="seraph-input sophia-ti-input"
            data-testid="ioc-search-input"
          />
          <Button onClick={handleSearch} disabled={loading} className="sophia-btn sophia-ti-button sophia-ti-button--cyan" data-testid="ioc-search-btn">
            {loading ? 'Searching...' : 'Search'}
          </Button>
        </div>

        {searchResult && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="mt-4">
            <SophiaIntelPanel
              tone={searchResult.matched ? 'magenta' : 'green'}
              className="p-4"
            >
              <div className="flex items-center gap-2 mb-2">
                {searchResult.matched ? (
                  <XCircle className="w-5 h-5" style={{ color: SOPHIA_INTEL_NEON.magenta.color }} />
                ) : (
                  <CheckCircle className="w-5 h-5" style={{ color: SOPHIA_INTEL_NEON.green.color }} />
                )}
                <span className="sophia-scan sophia-terminal-label font-semibold" style={{ color: searchResult.matched ? SOPHIA_INTEL_NEON.magenta.text : SOPHIA_INTEL_NEON.green.text }}>
                  {searchResult.matched ? 'THREAT DETECTED' : 'No Threat Found'}
                </span>
              </div>
              <p className="sophia-terminal-meta text-sm">
                Type: {searchResult.query_type} | Value: {searchResult.query_value}
              </p>
              {searchResult.indicator && (
                <div className="mt-3 p-3 sophia-command-bar">
                  <p className="sophia-terminal-value text-sm">Source: {searchResult.indicator.source}</p>
                  <p className="sophia-terminal-meta text-sm">Level: {searchResult.indicator.threat_level}</p>
                  <p className="sophia-terminal-meta text-sm">Confidence: {searchResult.indicator.confidence}%</p>
                </div>
              )}
            </SophiaIntelPanel>
          </motion.div>
        )}
      </SophiaIntelPanel>

      {/* Feed Status */}
      <SophiaIntelPanel tone="green" className="p-5">
        <div className="mb-4 flex items-center gap-2">
          <TrendingUp className="w-5 h-5" style={{ color: SOPHIA_INTEL_NEON.green.color, filter: `drop-shadow(0 0 8px ${SOPHIA_INTEL_NEON.green.glow})` }} />
          <h2 className="sophia-scan sophia-terminal-heading text-base">
            Feed Status
          </h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {stats?.by_feed && Object.entries(stats.by_feed).map(([name, data], index) => {
            const tone = ['cyan', 'magenta', 'green', 'purple'][index % 4];
            const t = SOPHIA_INTEL_NEON[tone];
            return (
              <SophiaIntelPanel key={name} tone={tone} className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="sophia-scan sophia-terminal-value font-medium capitalize" style={{ color: t.text }}>{name.replace(/_/g, ' ')}</p>
                    <p className="sophia-terminal-meta text-sm">{data.total?.toLocaleString() || 0} indicators</p>
                  </div>
                  <Badge variant="outline" className="sophia-badge-pulse" style={{ color: t.color, borderColor: t.color, background: t.bg, boxShadow: `0 0 12px ${t.glow}` }}>
                    Active
                  </Badge>
                </div>
                {data.last_updated && (
                  <p className="sophia-terminal-meta text-xs mt-2 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    Last updated: {new Date(data.last_updated).toLocaleString()}
                  </p>
                )}
              </SophiaIntelPanel>
            );
          })}
        </div>
      </SophiaIntelPanel>

      <SophiaIntelPanel tone="purple" className="p-5">
        <div className="mb-4 flex items-center gap-2">
          <AlertTriangle className="w-5 h-5" style={{ color: SOPHIA_INTEL_NEON.purple.color, filter: `drop-shadow(0 0 8px ${SOPHIA_INTEL_NEON.purple.glow})` }} />
          <h2 className="sophia-scan sophia-terminal-heading text-base">Recent Indicator Matches</h2>
        </div>
        {recentMatches.length === 0 ? (
          <p className="sophia-terminal-meta text-sm">No recent indicator matches.</p>
        ) : (
          <div className="space-y-3">
            {recentMatches.slice(0, 8).map((match, index) => {
              const tone = ['magenta', 'cyan', 'green', 'purple'][index % 4];
              const t = SOPHIA_INTEL_NEON[tone];
              return (
                <div
                  key={match.id || `${match.indicator_value}-${index}`}
                  className="sophia-ti-row"
                  style={{ borderColor: t.color, boxShadow: `0 0 12px ${t.glow}, inset 0 0 10px ${t.bg}` }}
                >
                  <div className="flex items-start gap-3 min-w-0">
                    <div className="mt-1" style={{ color: t.color, filter: `drop-shadow(0 0 6px ${t.glow})` }}>
                      {getTypeIcon(match.indicator_type || match.type)}
                    </div>
                    <div className="min-w-0">
                      <p className="sophia-flicker sophia-terminal-value text-sm truncate" style={{ color: '#e6fbff' }}>
                        {match.indicator_value || match.value || match.indicator || 'unknown indicator'}
                      </p>
                      <p className="sophia-terminal-meta text-xs">
                        {match.source || match.feed || 'feed'} · {match.threat_level || match.severity || 'matched'}
                      </p>
                    </div>
                  </div>
                  <Badge variant="outline" style={{ color: t.text, borderColor: `${t.color}99`, background: t.bg }}>
                    match
                  </Badge>
                </div>
              );
            })}
          </div>
        )}
      </SophiaIntelPanel>
    </div>
  );
};

export default ThreatIntelPage;
