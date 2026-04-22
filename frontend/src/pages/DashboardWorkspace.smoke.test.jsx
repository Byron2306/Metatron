import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import apiClient from '../lib/api';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import CommandWorkspacePage from './CommandWorkspacePage';
import DashboardPage from './DashboardPage';
import WorldViewPage from './WorldViewPage';

jest.mock('axios');
jest.mock('../context/AuthContext', () => ({
  useAuth: () => ({
    getAuthHeaders: () => ({ Authorization: 'Bearer smoke-token' }),
  }),
}));

jest.mock('./CommandCenterPage', () => () => <div>Command Center Tab Mock</div>);
jest.mock('./AlertsPage', () => () => <div>Alerts Tab Mock</div>);
jest.mock('./ThreatsPage', () => () => <div>Threats Tab Mock</div>);
jest.mock('./GraphWorld', () => () => <div>Graph World Mock</div>);

const worldState = {
  header: {
    risk_level: 'high',
    active_campaigns: 3,
    high_risk_identities: 2,
    critical_hosts: 1,
    active_containments: 4,
    last_state_change: '2026-04-13T12:00:00Z',
  },
  actions: [
    {
      action: 'contain_entity',
      entity_id: 'endpoint-7',
      reason: 'credential_theft',
    },
  ],
  hypotheses: [
    {
      candidate: 'Lateral movement via compromised admin session',
      score: 0.82,
    },
  ],
  hotspots: [
    {
      id: 'host-1',
      type: 'host',
      risk_score: 92,
    },
  ],
  recent_events: [
    {
      type: 'alert',
      id: 'alert-1',
      timestamp: '2026-04-13T12:05:00Z',
    },
  ],
  timeline: [
    {
      type: 'timeline',
      id: 'timeline-1',
      timestamp: '2026-04-13T12:06:00Z',
    },
  ],
  attack_path: {
    nodes: [{ id: 'host-1' }, { id: 'user-1' }],
    edges: [{ source: 'user-1', target: 'host-1', relation: 'accesses' }],
  },
  trust: {
    identity: 'degraded',
  },
};

const dashboardStats = {
  active_threats: 5,
  total_threats: 17,
  contained_threats: 4,
  resolved_threats: 8,
  recent_alerts: 6,
  threats_by_type: {
    malware: 4,
    phishing: 2,
  },
  threats_by_severity: {
    critical: 3,
    high: 5,
  },
  recent_threats: [
    {
      id: 'threat-1',
      name: 'Credential stuffing',
      type: 'phishing',
      severity: 'high',
      status: 'active',
      created_at: '2026-04-13T11:00:00Z',
      source_ip: '10.0.0.8',
    },
  ],
  recent_alerts_list: [
    {
      id: 'alert-1',
      title: 'Unusual sign-in velocity',
      message: 'Multiple login attempts detected',
      severity: 'high',
      type: 'identity',
      status: 'new',
      created_at: '2026-04-13T11:30:00Z',
    },
  ],
};

describe('dashboard workspace smoke coverage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('switches command workspace tabs from the dashboard shell', async () => {
    axios.get.mockImplementation((url) => {
      if (url.includes('/dashboard/stats')) {
        return Promise.resolve({ data: dashboardStats });
      }
      return Promise.resolve({ data: {} });
    });

    render(
      <MemoryRouter initialEntries={['/command']}>
        <Routes>
          <Route path="/command" element={<CommandWorkspacePage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText('Command Workspace')).toBeInTheDocument();
    expect(await screen.findByText('Threat Dashboard')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /command center/i }));
    expect(screen.getByText('Command Center Tab Mock')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /alerts/i }));
    expect(screen.getByText('Alerts Tab Mock')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /threats/i }));
    expect(screen.getByText('Threats Tab Mock')).toBeInTheDocument();
  });

  it('renders world view tabs and switches between overview, graph, and events', async () => {
    axios.get.mockImplementation((url) => {
      if (url.includes('/metatron/state')) {
        return Promise.resolve({ data: worldState });
      }
      return Promise.resolve({ data: {} });
    });

    render(
      <MemoryRouter initialEntries={['/world']}>
        <Routes>
          <Route path="/world" element={<WorldViewPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText('World View')).toBeInTheDocument();
    expect(screen.getByText(/Metatron Narrative/i)).toBeInTheDocument();
    expect(screen.getByText(/contain entity on endpoint-7/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /graph/i }));
    expect(screen.getByText('Graph World Mock')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /events/i }));
    expect(screen.getByText('World Events')).toBeInTheDocument();
    expect(screen.getByText(/alert: alert-1/i)).toBeInTheDocument();
    expect(screen.getByText('Evidence Timeline')).toBeInTheDocument();
  });
});

describe('dashboard page smoke coverage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders dashboard data and action buttons from the live stats payload', async () => {
    axios.get.mockResolvedValue({ data: dashboardStats });
    axios.post.mockResolvedValue({ data: { ok: true } });

    render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>,
    );

    expect(await screen.findByTestId('dashboard-page')).toBeInTheDocument();
    expect(screen.getByText('Threat Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Credential stuffing')).toBeInTheDocument();
    expect(screen.getByText('Active Threats')).toBeInTheDocument();
    expect(screen.getAllByText('5').length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole('button', { name: /load demo data/i }));
    await waitFor(() => {
      expect(axios.post).toHaveBeenCalled();
    });
    expect(screen.getByTestId('refresh-dashboard-btn')).toBeInTheDocument();
  });
});
