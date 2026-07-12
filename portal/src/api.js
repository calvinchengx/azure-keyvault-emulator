// Same-origin fetch wrapper. The portal is served by the emulator under
// /_emulator/portal/, so absolute /_emulator/* paths hit the same process; in
// dev, Vite proxies them to a running emulator. No auth — the portal only
// touches the unauthenticated control + portal-data surface.
async function call(method, path, body) {
  const resp = await fetch(path, {
    method,
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (resp.status === 204) return null;
  const data = await resp.json().catch(() => null);
  if (!resp.ok) throw new Error(data?.error?.message || data?.error || `HTTP ${resp.status}`);
  return data;
}

export const api = {
  get: (p) => call('GET', p),
  post: (p, b) => call('POST', p, b),
};

// Epoch seconds → readable UTC, or "—" for unset/zero.
export function fmtTime(epoch) {
  if (!epoch) return '—';
  return new Date(epoch * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}

export function copy(text) {
  navigator.clipboard?.writeText(text);
}
