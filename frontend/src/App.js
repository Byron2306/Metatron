import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Toaster } from "./components/ui/sonner";
import { AuthProvider, useAuth } from "./context/AuthContext";
import LoginPage from "./pages/LoginPage";
import NetworkTopologyPage from "./pages/NetworkTopologyPage";
import ThreatHuntingPage from "./pages/ThreatHuntingPage";
import HoneypotsPage from "./pages/HoneypotsPage";
import ReportsPage from "./pages/ReportsPage";
import AgentsPage from "./pages/AgentsPage";
import SettingsPage from "./pages/SettingsPage";
import TimelinePage from "./pages/TimelinePage";
import AuditLogPage from "./pages/AuditLogPage";
import ZeekPage from "./pages/ZeekPage";
import OsqueryFleetPage from "./pages/OsqueryFleetPage";
import RansomwarePage from "./pages/RansomwarePage";
import ContainerSecurityPage from "./pages/ContainerSecurityPage";
import VPNPage from "./pages/VPNPage";
import HoneyTokensPage from "./pages/HoneyTokensPage";
import ZeroTrustPage from "./pages/ZeroTrustPage";
import MLPredictionPage from "./pages/MLPredictionPage";
import SandboxPage from "./pages/SandboxPage";
import BrowserIsolationPage from "./pages/BrowserIsolationPage";
import KibanaDashboardsPage from "./pages/KibanaDashboardsPage";
import AgentCommandsPage from "./pages/AgentCommandsPage";
import AgentDetailsPage from "./pages/AgentDetailsPage";
import SwarmDashboard from "./pages/SwarmDashboard";
import AdvancedServicesPage from "./pages/AdvancedServicesPage";
import TacticalHeatmapPage from "./pages/TacticalHeatmapPage";
import VNSAlertsPage from "./pages/VNSAlertsPage";
import BrowserExtensionPage from "./pages/BrowserExtensionPage";
import SetupGuidePage from "./pages/SetupGuidePage";
import TenantsPage from "./pages/TenantsPage";
import UnifiedAgentPage from "./pages/UnifiedAgentPage";
import WorldViewPage from "./pages/WorldViewPage";
import CSPMPage from "./pages/CSPMPage";
import DeceptionPage from "./pages/DeceptionPage";
import KernelSensorsPage from "./pages/KernelSensorsPage";
import SecureBootPage from "./pages/SecureBootPage";
import IdentityProtectionPage from "./pages/IdentityProtectionPage";
import AIActivityWorkspacePage from "./pages/AIActivityWorkspacePage";
import ResponseOperationsPage from "./pages/ResponseOperationsPage";
import InvestigationWorkspacePage from "./pages/InvestigationWorkspacePage";
import EmailSecurityWorkspacePage from "./pages/EmailSecurityWorkspacePage";
import EndpointMobilityWorkspacePage from "./pages/EndpointMobilityWorkspacePage";
import CommandWorkspacePage from "./pages/CommandWorkspacePage";
import DetectionEngineeringWorkspacePage from "./pages/DetectionEngineeringWorkspacePage";
import Layout from "./components/Layout";
import "@/App.css";

const ProtectedRoute = ({ children }) => {
  const { user, loading } = useAuth();
  
  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-blue-500 font-mono text-xl animate-pulse">
          Initializing Defense System...
        </div>
      </div>
    );
  }
  
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  
  return children;
};

function App() {
  return (
    <AuthProvider>
      <div className="App noise-bg">
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route
              path="/"
              element={
                <ProtectedRoute>
                  <Layout />
                </ProtectedRoute>
              }
            >
              <Route index element={<Navigate to="/command" replace />} />
              <Route path="command" element={<CommandWorkspacePage />} />
              <Route path="dashboard" element={<Navigate to="/command?tab=dashboard" replace />} />
              <Route path="world" element={<WorldViewPage />} />
              <Route path="world/graph" element={<Navigate to="/world?tab=graph" replace />} />
              <Route path="ai-activity" element={<AIActivityWorkspacePage />} />
              <Route path="ai-detection" element={<Navigate to="/ai-activity?tab=signals" replace />} />
              <Route path="alerts" element={<Navigate to="/command?tab=alerts" replace />} />
              <Route path="threats" element={<Navigate to="/command?tab=threats" replace />} />
              <Route path="network" element={<NetworkTopologyPage />} />
              <Route path="hunting" element={<ThreatHuntingPage />} />
              <Route path="honeypots" element={<HoneypotsPage />} />
              <Route path="reports" element={<ReportsPage />} />
              <Route path="agents" element={<Navigate to="/unified-agent" replace />} />
              <Route path="response-operations" element={<ResponseOperationsPage />} />
              <Route path="quarantine" element={<Navigate to="/response-operations?tab=quarantine" replace />} />
              <Route path="response" element={<Navigate to="/response-operations?tab=automation" replace />} />
              <Route path="timeline" element={<TimelinePage />} />
              <Route path="audit" element={<AuditLogPage />} />
              <Route path="settings" element={<SettingsPage />} />
              <Route path="investigation" element={<InvestigationWorkspacePage />} />
              <Route path="threat-intel" element={<Navigate to="/investigation?tab=intel" replace />} />
              <Route path="detection-engineering" element={<DetectionEngineeringWorkspacePage />} />
              <Route path="sigma" element={<Navigate to="/detection-engineering?tab=sigma" replace />} />
              <Route path="zeek" element={<ZeekPage />} />
              <Route path="osquery-fleet" element={<OsqueryFleetPage />} />
              <Route path="atomic-validation" element={<Navigate to="/detection-engineering?tab=atomic" replace />} />
              <Route path="mitre-attack" element={<Navigate to="/detection-engineering?tab=mitre" replace />} />
              <Route path="ransomware" element={<RansomwarePage />} />
              <Route path="containers" element={<ContainerSecurityPage />} />
              <Route path="vpn" element={<VPNPage />} />
              <Route path="correlation" element={<Navigate to="/investigation?tab=correlation" replace />} />
              <Route path="edr" element={<Navigate to="/response-operations?tab=edr" replace />} />
              <Route path="soar" element={<Navigate to="/response-operations?tab=soar" replace />} />
              <Route path="honey-tokens" element={<HoneyTokensPage />} />
              <Route path="zero-trust" element={<ZeroTrustPage />} />
              <Route path="ml-prediction" element={<MLPredictionPage />} />
              <Route path="sandbox" element={<SandboxPage />} />
              <Route path="browser-isolation" element={<BrowserIsolationPage />} />
              <Route path="kibana" element={<KibanaDashboardsPage />} />
              <Route path="agent-commands" element={<Navigate to="/unified-agent" replace />} />
              <Route path="agent-commands/:agentId" element={<Navigate to="/unified-agent" replace />} />
              <Route path="cli-sessions" element={<Navigate to="/ai-activity?tab=sessions" replace />} />
              <Route path="swarm" element={<Navigate to="/unified-agent" replace />} />
              <Route path="ai-threats" element={<Navigate to="/ai-activity?tab=intelligence" replace />} />
              <Route path="command-center" element={<Navigate to="/command?tab=center" replace />} />
              <Route path="advanced" element={<AdvancedServicesPage />} />
              <Route path="heatmap" element={<TacticalHeatmapPage />} />
              <Route path="vns-alerts" element={<VNSAlertsPage />} />
              <Route path="browser-extension" element={<BrowserExtensionPage />} />
              <Route path="setup-guide" element={<SetupGuidePage />} />
              <Route path="tenants" element={<TenantsPage />} />
              <Route path="unified-agent" element={<UnifiedAgentPage />} />
              <Route path="cspm" element={<CSPMPage />} />
              <Route path="attack-paths" element={<Navigate to="/investigation?tab=paths" replace />} />
              <Route path="deception" element={<DeceptionPage />} />
              <Route path="kernel-sensors" element={<KernelSensorsPage />} />
              <Route path="secure-boot" element={<SecureBootPage />} />
              <Route path="identity" element={<IdentityProtectionPage />} />
              <Route path="email-security" element={<EmailSecurityWorkspacePage />} />
              <Route path="endpoint-mobility" element={<EndpointMobilityWorkspacePage />} />
              <Route path="email-protection" element={<Navigate to="/email-security?tab=protection" replace />} />
              <Route path="email-gateway" element={<Navigate to="/email-security?tab=gateway" replace />} />
              <Route path="mobile-security" element={<Navigate to="/endpoint-mobility?tab=mobile" replace />} />
              <Route path="mdm" element={<Navigate to="/endpoint-mobility?tab=mdm" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
        <Toaster 
          position="top-right" 
          toastOptions={{
            style: {
              background: '#0F172A',
              border: '1px solid #1E293B',
              color: '#F8FAFC',
            },
          }}
        />
      </div>
    </AuthProvider>
  );
}

export default App;
