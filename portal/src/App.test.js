import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import App from './App.svelte';

beforeEach(() => {
  // The shell pings /health and views fetch data on mount; stub both so the
  // component mounts without a backend.
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: () => Promise.resolve({ counts: {}, vaults: [], clock: { now: 0, offset: 0, frozen: false }, value: [] }),
  }));
  location.hash = '';
});

describe('App shell', () => {
  it('renders the wordmark and navigation', () => {
    render(App);
    expect(screen.getByText('Azure Key Vault Emulator')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Secrets' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Keys' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Fault injection' })).toBeInTheDocument();
  });

  it('routes from the location hash', () => {
    location.hash = 'faults';
    render(App);
    expect(screen.getByRole('heading', { name: 'Fault injection' })).toBeInTheDocument();
  });
});
