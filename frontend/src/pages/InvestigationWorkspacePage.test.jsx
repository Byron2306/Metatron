import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { render, screen } from '@testing-library/react';
import InvestigationWorkspacePage from './InvestigationWorkspacePage';

jest.mock('./ThreatIntelPage', () => () => <div>Threat Intel Mock</div>);
jest.mock('./CorrelationPage', () => () => <div>Correlation Mock</div>);
jest.mock('./AttackPathsPage', () => () => <div>Attack Paths Mock</div>);

describe('InvestigationWorkspacePage', () => {
  it('renders the default investigation tab', () => {
    render(
      <MemoryRouter initialEntries={['/investigation']}>
        <Routes>
          <Route path="/investigation" element={<InvestigationWorkspacePage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(screen.getByText('Investigation Workspace')).toBeInTheDocument();
    expect(screen.getByText('Threat Intel Mock')).toBeInTheDocument();
  });
});
