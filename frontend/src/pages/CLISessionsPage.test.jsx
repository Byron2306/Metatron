import { render, screen, waitFor } from '@testing-library/react';
import apiClient from '../lib/api';
import CLISessionsPage from './CLISessionsPage';

jest.mock('axios');
jest.mock('../context/AuthContext', () => ({
  useAuth: () => ({ token: 'test-token' }),
}));
jest.mock('sonner', () => ({
  toast: {
    error: jest.fn(),
    success: jest.fn(),
    info: jest.fn(),
  },
}));

describe('CLISessionsPage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('shows deterministic fallback session data when APIs return empty datasets', async () => {
    axios.get.mockImplementation((url) => {
      if (url.includes('/cli/sessions/all')) {
        return Promise.resolve({ data: { summaries: [] } });
      }
      if (url.includes('/deception/hits')) {
        return Promise.resolve({ data: { hits: [] } });
      }
      if (url.includes('/ai-threats/aatl/assessments')) {
        return Promise.resolve({ data: { assessments: [] } });
      }
      return Promise.resolve({ data: { commands: [] } });
    });

    render(<CLISessionsPage />);

    await waitFor(() => {
      expect(screen.getAllByText('prod-admin-ws-07').length).toBeGreaterThan(0);
    });

    expect(screen.getByText('AI-Agentic Detection Dashboard')).toBeInTheDocument();
    expect(screen.getByText('eng-jumpbox-02')).toBeInTheDocument();
    expect(screen.getByText(/DECOY TOUCHED/i)).toBeInTheDocument();
  });
});
