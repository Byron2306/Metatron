import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { motion } from 'framer-motion';
import { 
  Shield, Play, Square, Plus, Trash2, Download,
  Users, Key, Lock, Unlock, Globe, Activity, CheckCircle, XCircle
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { toast } from 'sonner';
import SeraphPageHeader from '../components/SeraphPageHeader';

const rawBackendUrl = process.env.REACT_APP_BACKEND_URL?.trim();
const API = rawBackendUrl ? `${rawBackendUrl}/api` : '/api';

const VPN_ACCENTS = {
  violet: { border: 'rgba(188,19,254,0.38)', glow: 'rgba(188,19,254,0.14)' },
  green: { border: 'rgba(57,255,20,0.34)', glow: 'rgba(57,255,20,0.12)' },
  gold: { border: 'rgba(251,191,36,0.36)', glow: 'rgba(251,191,36,0.12)' },
};

const vpnPanelStyle = (accent) => ({
  background: 'linear-gradient(160deg, rgba(8,18,34,0.92), rgba(3,9,18,0.96))',
  border: `1px solid ${accent.border}`,
  boxShadow: `0 0 14px ${accent.glow}, inset 0 0 8px rgba(255,255,255,0.02)`,
  borderRadius: '14px',
});

const VPNPage = () => {
  const { token } = useAuth();
  const [status, setStatus] = useState(null);
  const [peers, setPeers] = useState([]);
  const [newPeerName, setNewPeerName] = useState('');
  const [loading, setLoading] = useState(false);
  const [selectedPeerConfig, setSelectedPeerConfig] = useState(null);
  const [vpnConfig, setVpnConfig] = useState({
    enabled: true,
    server_address: '10.200.200.1/24',
    port: 51820,
    dns_servers: ['1.1.1.1', '8.8.8.8'],
    server_endpoint: '',
  });

  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    fetchStatus();
    fetchConfig();
    fetchPeers();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  const fetchStatus = async () => {
    try {
      const res = await axios.get(`${API}/vpn/status`, { headers });
      setStatus(res.data);
      const remoteConfig = res.data?.config || {};
      setVpnConfig((prev) => ({
        ...prev,
        enabled: remoteConfig.enabled ?? prev.enabled,
        server_address: res.data?.server?.address || prev.server_address,
        port: remoteConfig.port ?? prev.port,
        dns_servers: remoteConfig.dns || remoteConfig.dns_servers || prev.dns_servers,
        server_endpoint: res.data?.server?.endpoint || prev.server_endpoint,
      }));
    } catch (err) {
      toast.error('Failed to fetch VPN status');
    }
  };

  const fetchConfig = async () => {
    try {
      const res = await axios.get(`${API}/vpn/config`, { headers });
      if (!res.data) return;
      setVpnConfig({
        enabled: res.data.enabled ?? true,
        server_address: res.data.server_address || '10.200.200.1/24',
        port: res.data.port || 51820,
        dns_servers: res.data.dns_servers || ['1.1.1.1', '8.8.8.8'],
        server_endpoint: res.data.server_endpoint || '',
      });
    } catch (err) {
      console.error('Failed to fetch VPN config');
    }
  };

  const fetchPeers = async () => {
    try {
      const res = await axios.get(`${API}/vpn/peers`, { headers });
      setPeers(res.data.peers || []);
    } catch (err) {
      console.error('Failed to fetch peers');
    }
  };

  const handleInitialize = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${API}/vpn/initialize`, {}, { headers });
      if (res.data?.status === 'error') {
        toast.error(res.data?.error || 'Failed to initialize VPN');
      } else {
        toast.success('VPN server initialized');
        await fetchStatus();
      }
    } catch (err) {
      toast.error('Failed to initialize VPN');
    } finally {
      setLoading(false);
    }
  };

  const handleStart = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${API}/vpn/start`, {}, { headers });
      if (res.data?.status === 'error') {
        toast.error(res.data?.error || 'Failed to start VPN');
      } else if (res.data?.status === 'managed_externally') {
        toast.info(res.data?.message || 'VPN is managed by the external WireGuard container');
        await fetchStatus();
      } else if (res.data?.status === 'started') {
        toast.success(res.data?.message || 'VPN server started');
        await fetchStatus();
      } else {
        toast.info(res.data?.message || 'VPN start request accepted');
        await fetchStatus();
      }
    } catch (err) {
      toast.error('Failed to start VPN');
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${API}/vpn/stop`, {}, { headers });
      if (res.data?.status === 'error') {
        toast.error(res.data?.error || 'Failed to stop VPN');
      } else {
        if (res.data?.status === 'managed_externally') {
          toast.info(res.data?.message || 'VPN is managed by external WireGuard service');
        } else {
          toast.info(res.data?.message || 'VPN server stopped');
        }
        await fetchStatus();
      }
    } catch (err) {
      toast.error('Failed to stop VPN');
    } finally {
      setLoading(false);
    }
  };

  const handleAddPeer = async () => {
    if (!newPeerName.trim()) return;
    try {
      await axios.post(`${API}/vpn/peers`, { name: newPeerName.trim() }, { headers });
      toast.success('Peer added');
      setNewPeerName('');
      fetchPeers();
    } catch (err) {
      toast.error('Failed to add peer');
    }
  };

  const handleRemovePeer = async (peerId) => {
    try {
      await axios.delete(`${API}/vpn/peers/${peerId}`, { headers });
      toast.success('Peer removed');
      fetchPeers();
    } catch (err) {
      toast.error('Failed to remove peer');
    }
  };

  const handleGetConfig = async (peerId, peerName) => {
    try {
      const res = await axios.get(`${API}/vpn/peers/${peerId}/config`, { headers });
      // Create downloadable file
      const blob = new Blob([res.data], { type: 'text/plain' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${peerName || peerId}.conf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      toast.success(`Config downloaded: ${peerName}.conf`);
    } catch (err) {
      toast.error('Failed to get peer config');
    }
  };

  const handleToggleKillSwitch = async () => {
    try {
      if (status?.kill_switch?.enabled) {
        await axios.post(`${API}/vpn/kill-switch/disable`, {}, { headers });
        toast.info('Kill switch disabled');
      } else {
        await axios.post(`${API}/vpn/kill-switch/enable`, {}, { headers });
        toast.success('Kill switch enabled');
      }
      fetchStatus();
    } catch (err) {
      toast.error('Failed to toggle kill switch');
    }
  };

  const handleSaveConfig = async () => {
    setLoading(true);
    try {
      await axios.put(`${API}/vpn/config`, {
        enabled: vpnConfig.enabled,
        server_address: vpnConfig.server_address,
        port: Number(vpnConfig.port),
        dns_servers: Array.isArray(vpnConfig.dns_servers)
          ? vpnConfig.dns_servers
          : String(vpnConfig.dns_servers || '').split(',').map((item) => item.trim()).filter(Boolean),
        server_endpoint: vpnConfig.server_endpoint,
      }, { headers });
      toast.success('VPN configuration saved');
      await fetchStatus();
      await fetchConfig();
    } catch (err) {
      toast.error('Failed to save VPN configuration');
    } finally {
      setLoading(false);
    }
  };

  const serverStatus = status?.server?.status || 'unknown';
  const serverStatusLabel = serverStatus === 'managed_externally'
    ? 'active via wireguard service'
    : serverStatus.replace(/_/g, ' ');

  return (
    <div className="space-y-6" data-testid="vpn-page">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <SeraphPageHeader
          eyebrow="seraph · vpn · wireguard mesh"
          title="VPN Integration"
          tagline="> WireGuard VPN server management"
          accent="green"
          status={serverStatusLabel.toUpperCase()}
        />
        <div className="flex gap-2">
          {serverStatus === 'not_installed' ? (
            <Button className="sophia-btn arm-button" onClick={handleInitialize} disabled={loading} style={{ backgroundImage: 'linear-gradient(135deg, rgba(251,191,36,0.95), rgba(255,43,214,0.9))', color: '#041018', border: '1px solid rgba(251,191,36,0.36)' }}>
              <Key className="w-4 h-4 mr-2" />
              Initialize Server
            </Button>
          ) : serverStatus === 'running' ? (
            <Button className="sophia-btn arm-button" onClick={handleStop} disabled={loading} style={{ backgroundImage: 'linear-gradient(135deg, rgba(255,59,48,0.95), rgba(255,122,26,0.9))', color: '#ffffff', border: '1px solid rgba(255,122,26,0.32)' }}>
              <Square className="w-4 h-4 mr-2" />
              Stop Server
            </Button>
          ) : serverStatus === 'managed_externally' ? (
            <Button className="sophia-btn arm-button" onClick={fetchStatus} disabled={loading} style={{ backgroundImage: 'linear-gradient(135deg, rgba(57,255,20,0.95), rgba(0,240,255,0.9))', color: '#041018', border: '1px solid rgba(0,240,255,0.3)' }}>
              <Activity className="w-4 h-4 mr-2" />
              Refresh Service Status
            </Button>
          ) : (
            <Button className="sophia-btn arm-button" onClick={handleStart} disabled={loading} style={{ backgroundImage: 'linear-gradient(135deg, rgba(57,255,20,0.95), rgba(0,240,255,0.9))', color: '#041018', border: '1px solid rgba(0,240,255,0.3)' }}>
              <Play className="w-4 h-4 mr-2" />
              Start Server
            </Button>
          )}
        </div>
      </div>

      <Card style={vpnPanelStyle(VPN_ACCENTS.violet)}>
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Globe className="w-5 h-5" style={{ color: '#bc13fe' }} />
            VPN Configuration
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <p className="text-slate-400 text-sm mb-2">Server Address</p>
              <Input
                value={vpnConfig.server_address}
                onChange={(e) => setVpnConfig((prev) => ({ ...prev, server_address: e.target.value }))}
                className="bg-slate-800 border-slate-700 text-white"
              />
            </div>
            <div>
              <p className="text-slate-400 text-sm mb-2">Port</p>
              <Input
                type="number"
                value={vpnConfig.port}
                onChange={(e) => setVpnConfig((prev) => ({ ...prev, port: e.target.value }))}
                className="bg-slate-800 border-slate-700 text-white"
              />
            </div>
            <div>
              <p className="text-slate-400 text-sm mb-2">DNS Servers</p>
              <Input
                value={Array.isArray(vpnConfig.dns_servers) ? vpnConfig.dns_servers.join(', ') : vpnConfig.dns_servers}
                onChange={(e) => setVpnConfig((prev) => ({
                  ...prev,
                  dns_servers: e.target.value.split(',').map((item) => item.trim()).filter(Boolean),
                }))}
                className="bg-slate-800 border-slate-700 text-white"
              />
            </div>
            <div>
              <p className="text-slate-400 text-sm mb-2">Server Endpoint</p>
              <Input
                value={vpnConfig.server_endpoint}
                onChange={(e) => setVpnConfig((prev) => ({ ...prev, server_endpoint: e.target.value }))}
                className="bg-slate-800 border-slate-700 text-white"
              />
            </div>
          </div>
          <div className="flex items-center justify-between mt-4 p-3 rounded-lg border border-slate-700 bg-slate-800/40">
            <div>
              <p className="text-white font-medium">VPN Enabled</p>
              <p className="text-slate-400 text-sm">Toggle configuration directly from the dashboard</p>
            </div>
            <Button
              variant={vpnConfig.enabled ? 'default' : 'outline'}
              className={vpnConfig.enabled ? 'bg-green-600 hover:bg-green-700' : 'border-slate-600 text-slate-300'}
              onClick={() => setVpnConfig((prev) => ({ ...prev, enabled: !prev.enabled }))}
            >
              {vpnConfig.enabled ? 'Enabled' : 'Disabled'}
            </Button>
          </div>
          <div className="mt-4 flex justify-end">
            <Button className="sophia-btn arm-button" onClick={handleSaveConfig} disabled={loading} style={{ backgroundImage: 'linear-gradient(135deg, rgba(255,43,214,0.95), rgba(251,191,36,0.9))', color: '#041018', border: '1px solid rgba(255,43,214,0.35)' }}>
              Save Configuration
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          className="p-4 rounded-lg border"
          style={vpnPanelStyle(serverStatus === 'running' || serverStatus === 'managed_externally' ? VPN_ACCENTS.green : serverStatus === 'not_installed' ? VPN_ACCENTS.gold : VPN_ACCENTS.violet)}>
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${serverStatus === 'running' || serverStatus === 'managed_externally' ? 'bg-green-500/20' : serverStatus === 'not_installed' ? 'bg-amber-500/20' : 'bg-slate-800'}`}>
              {serverStatus === 'running' || serverStatus === 'managed_externally' ? (
                <CheckCircle className="w-5 h-5 text-green-400" />
              ) : serverStatus === 'not_installed' ? (
                <XCircle className="w-5 h-5 text-amber-400" />
              ) : (
                <Activity className="w-5 h-5 text-slate-400" />
              )}
            </div>
            <div>
              <p className="sophia-terminal-label text-sm">Server Status</p>
              <p className={`sophia-terminal-value font-bold capitalize ${serverStatus === 'running' ? 'text-green-400' : serverStatus === 'managed_externally' ? 'text-cyan-400' : serverStatus === 'not_installed' ? 'text-amber-400' : 'text-slate-400'}`}>
                {serverStatusLabel}
              </p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="p-4" style={vpnPanelStyle(VPN_ACCENTS.violet)}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ background: 'rgba(188,19,254,0.14)' }}>
              <Users className="w-5 h-5" style={{ color: '#bc13fe' }} />
            </div>
            <div>
              <p className="sophia-terminal-label text-sm">Connected Peers</p>
              <p className="sophia-terminal-value text-2xl font-bold text-white">{peers.length}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          className="p-4" style={vpnPanelStyle(VPN_ACCENTS.violet)}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ background: 'rgba(251,191,36,0.14)' }}>
              <Globe className="w-5 h-5" style={{ color: '#fbbf24' }} />
            </div>
            <div>
              <p className="sophia-terminal-label text-sm">Port</p>
              <p className="sophia-terminal-value text-2xl font-bold text-white">{status?.config?.port || 51820}</p>
            </div>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
          className="p-4 rounded-lg border cursor-pointer"
          style={vpnPanelStyle(status?.kill_switch?.enabled ? VPN_ACCENTS.green : VPN_ACCENTS.violet)}
          onClick={handleToggleKillSwitch}>
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${status?.kill_switch?.enabled ? 'bg-green-500/20' : 'bg-slate-800'}`}>
              {status?.kill_switch?.enabled ? 
                <Lock className="w-5 h-5 text-green-400" /> : 
                <Unlock className="w-5 h-5 text-slate-400" />
              }
            </div>
            <div>
              <p className="sophia-terminal-label text-sm">Kill Switch</p>
              <p className={`sophia-terminal-value font-bold ${status?.kill_switch?.enabled ? 'text-green-400' : 'text-slate-400'}`}>
                {status?.kill_switch?.enabled ? 'Enabled' : 'Disabled'}
              </p>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Peer Management */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Users className="w-5 h-5 text-blue-400" />
            VPN Peers
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4 mb-4">
            <Input
              placeholder="Peer name (e.g., agent-001)"
              value={newPeerName}
              onChange={(e) => setNewPeerName(e.target.value)}
              className="bg-slate-800 border-slate-700 text-white"
            />
            <Button onClick={handleAddPeer}>
              <Plus className="w-4 h-4 mr-1" />
              Add Peer
            </Button>
          </div>

          {peers.length > 0 ? (
            <div className="space-y-2">
              {peers.map((peer) => (
                <div key={peer.peer_id} 
                  className="flex items-center justify-between p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10 rounded bg-indigo-500/10 flex items-center justify-center">
                      <Users className="w-5 h-5 text-indigo-400" />
                    </div>
                    <div>
                      <p className="text-white font-medium">{peer.name}</p>
                      <p className="text-slate-400 text-sm font-mono">{peer.allowed_ips}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className={peer.status === 'active' ? 'text-green-400 border-green-500/30' : 'text-slate-400 border-slate-500/30'}>
                      {peer.status}
                    </Badge>
                    <Button size="sm" variant="outline" onClick={() => handleGetConfig(peer.peer_id, peer.name)} data-testid={`download-peer-${peer.peer_id}`}>
                      <Download className="w-4 h-4" />
                    </Button>
                    <Button size="sm" variant="destructive" onClick={() => handleRemovePeer(peer.peer_id)}>
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-slate-400">
              <Users className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No VPN peers configured</p>
              <p className="text-sm">Add peers to allow secure connections</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Peer Config Modal */}
      {selectedPeerConfig && (
        <Card className="bg-slate-900/50 border-slate-800">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-white flex items-center gap-2">
              <Key className="w-5 h-5 text-amber-400" />
              Peer Configuration
            </CardTitle>
            <Button size="sm" variant="ghost" onClick={() => setSelectedPeerConfig(null)}>
              Close
            </Button>
          </CardHeader>
          <CardContent>
            <pre className="bg-slate-800 p-4 rounded-lg text-green-400 text-sm font-mono overflow-x-auto whitespace-pre-wrap">
              {selectedPeerConfig}
            </pre>
            <p className="text-slate-400 text-sm mt-4">
              Copy this configuration to the client's WireGuard config file.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Installation Note */}
      {serverStatus === 'not_installed' && (
        <Card className="bg-amber-500/10 border-amber-500/30">
          <CardContent className="py-4">
            <div className="flex items-center gap-4">
              <Shield className="w-8 h-8 text-amber-400" />
              <div>
                <p className="text-amber-400 font-medium">WireGuard Not Installed</p>
                <p className="text-slate-400 text-sm">
                  Install WireGuard on your server: <code className="bg-slate-800 px-2 py-1 rounded text-xs">apt install wireguard</code>
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Server Info */}
      {status?.server?.public_key && (
        <Card className="bg-indigo-500/10 border-indigo-500/30">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Key className="w-5 h-5 text-indigo-400" />
              Server Information
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <p className="text-slate-400 text-sm mb-1">Server Public Key</p>
                <code className="text-xs font-mono text-white bg-slate-800 px-2 py-1 rounded block overflow-x-auto">
                  {status.server.public_key}
                </code>
              </div>
              <div>
                <p className="text-slate-400 text-sm mb-1">VPN Endpoint</p>
                <code className="text-xs font-mono text-white bg-slate-800 px-2 py-1 rounded block">
                  {window.location.hostname}:{status?.config?.port || 51820}
                </code>
              </div>
            </div>
            <div className="mt-4 p-3 bg-slate-800/50 rounded border border-slate-700">
              <p className="text-sm text-slate-300 mb-2">
                <strong>How to connect:</strong>
              </p>
              <ol className="text-xs text-slate-400 list-decimal list-inside space-y-1">
                <li>Add a VPN peer using the form above</li>
                <li>Download the peer configuration file</li>
                <li>Import into WireGuard client on your device</li>
                <li>Connect and verify VPN status</li>
              </ol>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default VPNPage;
