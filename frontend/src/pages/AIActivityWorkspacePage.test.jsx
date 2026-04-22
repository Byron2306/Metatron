import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { render, screen } from '@testing-library/react';
import AIActivityWorkspacePage from './AIActivityWorkspacePage';

jest.mock('./AIDetectionPage', () => () => <div>AI Detection Mock</div>);
jest.mock('./AIThreatIntelligence', () => () => <div>AI Threat Intelligence Mock</div>);
jest.mock('./CLISessionsPage', () => () => <div>CLI Sessions Mock</div>);

describe('AIActivityWorkspacePage', () => {
  it('renders the default AI activity tab', () => {
    render(
      <MemoryRouter initialEntries={['/ai-activity']}>
        <Routes>
          <Route path="/ai-activity" element={<AIActivityWorkspacePage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText('AI Activity Workspace')).toBeInTheDocument();
    expect(screen.getByText('AI Detection Mock')).toBeInTheDocument();
  });

  it('renders the session intelligence tab when selected', () => {
    render(
      <MemoryRouter initialEntries={['/ai-activity?tab=sessions']}>
        <Routes>
          <Route path="/ai-activity" element={<AIActivityWorkspacePage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText('CLI Sessions Mock')).toBeInTheDocument();
  });
});
