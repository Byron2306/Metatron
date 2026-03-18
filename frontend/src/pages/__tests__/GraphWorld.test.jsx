jest.mock('axios', () => ({ get: jest.fn() }))
// Mock the force-graph module (ESM) so Jest doesn't try to parse it from node_modules
jest.mock('react-force-graph-2d', () => {
  return () => {
    const React = require('react')
    return React.createElement('div', { 'data-testid': 'force-graph-mock' })
  }
})

import React from 'react'
import { render, screen } from '@testing-library/react'
import axios from 'axios'
import GraphWorld from '../GraphWorld'

describe('GraphWorld', () => {
  test('renders loading then nodes', async () => {
    axios.get.mockResolvedValue({ data: { entities: [{ id: 'a', name: 'Alpha', type: 'host' }], relationships: [{ source: 'a', target: 'b', score: 1 }] } })
    render(<GraphWorld />)
    expect(screen.getByText(/Loading world state/i)).toBeInTheDocument()
    // wait for mocked graph to appear
    const el = await screen.findByTestId('force-graph-mock')
    expect(el).toBeInTheDocument()
  })
})
