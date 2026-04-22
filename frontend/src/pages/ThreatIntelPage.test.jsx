import { render, screen, waitFor } from '@testing-library/react';
import apiClient from '../lib/api';
import ThreatIntelPage from './ThreatIntelPage';

jest.mock('axios');
jest.mock('../context/AuthContext', () => ({
  useAuth: () => ({
    token: 'threat-intel-test-token',
  }),
}));

describe('ThreatIntelPage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders without hitting the jobs initialization TDZ and loads dashboard sections', async () => {
    axios.get.mockImplementation((url) => {
      if (url.includes('/threat-intel/stats')) {
        return Promise.resolve({
          data: {
            total_indicators: 42,
            enabled_feeds: ['abusech'],
            by_type: { ip: 10, url: 5 },
            by_feed: {
              abusech: { total: 42, last_updated: '2026-04-13T00:00:00Z' },
            },
          },
        });
      }

      if (url.includes('/threat-intel/matches/recent')) {
        return Promise.resolve({ data: [] });
      }

      if (url.includes('/integrations/jobs')) {
        return Promise.resolve({
          data: [
            { id: 'job-1', tool: 'amass', status: 'queued', updated_at: '2026-04-13T00:00:00Z' },
          ],
        });
      }

      if (url.includes('/unified/agents')) {
        return Promise.resolve({
          data: {
            agents: [{ agent_id: 'agent-1', status: 'online' }],
          },
        });
      }

      if (url.includes('/integrations/runtime/tools')) {
        return Promise.resolve({
          data: {
            tools: ['amass', 'sigma'],
          },
        });
      }

      return Promise.resolve({ data: {} });
    });

    render(<ThreatIntelPage />);

    expect(await screen.findByTestId('threat-intel-page')).toBeInTheDocument();
    expect(screen.getByText('Threat Intelligence')).toBeInTheDocument();
    expect(screen.getAllByText('42').length).toBeGreaterThan(0);

    await waitFor(() => {
      expect(axios.get).toHaveBeenCalledWith(
        '/api/integrations/jobs',
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer threat-intel-test-token',
          }),
        }),
      );
    });
  });
});
