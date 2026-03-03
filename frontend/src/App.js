import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Toaster } from "./components/ui/sonner";
import { AuthProvider, useAuth } from "./context/AuthContext";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import AIDetectionPage from "./pages/AIDetectionPage";
import AlertsPage from "./pages/AlertsPage";
import ThreatsPage from "./pages/ThreatsPage";
import NetworkTopologyPage from "./pages/NetworkTopologyPage";
import ThreatHuntingPage from "./pages/ThreatHuntingPage";
import HoneypotsPage from "./pages/HoneypotsPage";
import ReportsPage from "./pages/ReportsPage";
import AgentsPage from "./pages/AgentsPage";
import QuarantinePage from "./pages/QuarantinePage";
import SettingsPage from "./pages/SettingsPage";
import ThreatResponsePage from "./pages/ThreatResponsePage";
import TimelinePage from "./pages/TimelinePage";
import AuditLogPage from "./pages/AuditLogPage";
import ThreatIntelPage from "./pages/ThreatIntelPage";
import RansomwarePage from "./pages/RansomwarePage";
import ContainerSecurityPage from "./pages/ContainerSecurityPage";
import VPNPage from "./pages/VPNPage";
import CorrelationPage from "./pages/CorrelationPage";
import EDRPage from "./pages/EDRPage";
import SOARPage from "./pages/SOARPage";
import HoneyTokensPage from "./pages/HoneyTokensPage";
import ZeroTrustPage from "./pages/ZeroTrustPage";
import MLPredictionPage from "./pages/MLPredictionPage";
import SandboxPage from "./pages/SandboxPage";
import BrowserIsolationPage from "./pages/BrowserIsolationPage";
import KibanaDashboardsPage from "./pages/KibanaDashboardsPage";
import AgentCommandsPage from "./pages/AgentCommandsPage";
import AgentDetailsPage from "./pages/AgentDetailsPage";
import CLISessionsPage from "./pages/CLISessionsPage";
import SwarmDashboard from "./pages/SwarmDashboard";
import AIThreatIntelligence from "./pages/AIThreatIntelligence";
import CommandCenterPage from "./pages/CommandCenterPage";
import AdvancedServicesPage from "./pages/AdvancedServicesPage";
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
              <Route index element={<DashboardPage />} />
              <Route path="dashboard" element={<DashboardPage />} />
              <Route path="ai-detection" element={<AIDetectionPage />} />
              <Route path="alerts" element={<AlertsPage />} />
              <Route path="threats" element={<ThreatsPage />} />
              <Route path="network" element={<NetworkTopologyPage />} />
              <Route path="hunting" element={<ThreatHuntingPage />} />
              <Route path="honeypots" element={<HoneypotsPage />} />
              <Route path="reports" element={<ReportsPage />} />
              <Route path="agents" element={<AgentsPage />} />
              <Route path="quarantine" element={<QuarantinePage />} />
              <Route path="response" element={<ThreatResponsePage />} />
              <Route path="timeline" element={<TimelinePage />} />
              <Route path="audit" element={<AuditLogPage />} />
              <Route path="settings" element={<SettingsPage />} />
              <Route path="threat-intel" element={<ThreatIntelPage />} />
              <Route path="ransomware" element={<RansomwarePage />} />
              <Route path="containers" element={<ContainerSecurityPage />} />
              <Route path="vpn" element={<VPNPage />} />
              <Route path="correlation" element={<CorrelationPage />} />
              <Route path="edr" element={<EDRPage />} />
              <Route path="soar" element={<SOARPage />} />
              <Route path="honey-tokens" element={<HoneyTokensPage />} />
              <Route path="zero-trust" element={<ZeroTrustPage />} />
              <Route path="ml-prediction" element={<MLPredictionPage />} />
              <Route path="sandbox" element={<SandboxPage />} />
              <Route path="browser-isolation" element={<BrowserIsolationPage />} />
              <Route path="kibana" element={<KibanaDashboardsPage />} />
              <Route path="agent-commands" element={<AgentCommandsPage />} />
              <Route path="agent-commands/:agentId" element={<AgentDetailsPage />} />
              <Route path="cli-sessions" element={<CLISessionsPage />} />
              <Route path="swarm" element={<SwarmDashboard />} />
              <Route path="ai-threats" element={<AIThreatIntelligence />} />
              <Route path="command-center" element={<CommandCenterPage />} />
              <Route path="advanced" element={<AdvancedServicesPage />} />
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
