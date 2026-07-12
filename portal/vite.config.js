import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// The portal is served by the Go binary under /_emulator/portal/, so assets
// resolve from that absolute base regardless of the current hash route.
export default defineConfig(({ mode }) => ({
  base: '/_emulator/portal/',
  plugins: [svelte()],
  build: { outDir: 'dist', emptyOutDir: true },
  // Only under Vitest, resolve Svelte's client (browser) build so components
  // mount in jsdom. In dev/build we must NOT override resolve.conditions or the
  // bundle silently resolves the server build and never mounts.
  resolve: mode === 'test' ? { conditions: ['browser'] } : {},
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./vitest-setup.js'],
    // Unit tests only — the Playwright mount smoke lives in smoke/*.spec.js.
    include: ['src/**/*.test.js'],
  },
  // Dev only: forward the control + portal-data API to a running emulator
  // (start it with `-disable-tls -addr :8484`). The prefixes are precise so
  // they don't swallow the portal's own static path at /_emulator/portal/.
  server: {
    proxy: {
      '/_emulator/portal/data': { target: 'http://localhost:8484', changeOrigin: true, secure: false },
      '/_emulator/clock': { target: 'http://localhost:8484', changeOrigin: true, secure: false },
      '/_emulator/faults': { target: 'http://localhost:8484', changeOrigin: true, secure: false },
      '/_emulator/permissions': { target: 'http://localhost:8484', changeOrigin: true, secure: false },
      '/health': { target: 'http://localhost:8484', changeOrigin: true, secure: false },
    },
  },
}));
