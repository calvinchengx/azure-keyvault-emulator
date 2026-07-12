import { defineConfig } from '@playwright/test';

// Serves the *built* dist via `vite preview` and runs the mount smoke test —
// the only check that catches a bundle which builds but never mounts in a real
// browser (unit tests and `vite build` both pass in that failure mode).
export default defineConfig({
  testDir: './smoke',
  use: { baseURL: 'http://localhost:4174/_emulator/portal/' },
  webServer: {
    command: 'vite preview --port 4174 --strictPort',
    url: 'http://localhost:4174/_emulator/portal/',
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
