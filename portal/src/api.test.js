import { describe, it, expect, vi, afterEach } from 'vitest';
import { api, fmtTime } from './api.js';

afterEach(() => vi.restoreAllMocks());

describe('api', () => {
  it('parses a JSON body on success', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ value: [1, 2] }),
    }));
    expect(await api.get('/x')).toEqual({ value: [1, 2] });
  });

  it('throws the emulator error message on failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      json: () => Promise.resolve({ error: { message: 'SecretNotFound' } }),
    }));
    await expect(api.get('/x')).rejects.toThrow('SecretNotFound');
  });

  it('returns null on 204', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, status: 204 }));
    expect(await api.post('/x', {})).toBeNull();
  });
});

describe('fmtTime', () => {
  it('renders epoch seconds as UTC and dashes for zero', () => {
    expect(fmtTime(0)).toBe('—');
    expect(fmtTime(1_600_000_000)).toBe('2020-09-13 12:26:40Z');
  });
});
