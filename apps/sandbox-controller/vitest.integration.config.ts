import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// The same .env as docker compose, for the broker / MinIO addresses and the controller's own
// credentials only. Integration suites build the controller config from explicit env objects
// (never the whole .env: it holds keys the controller refuses). Values are never printed.
const envFile = resolve(__dirname, '../../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

// Focused suites (step 4.6 §9.2, §9.3): the real broker and MinIO; the runner suites
// (integration/runner/**, WP4) also need Docker and the exec override. Never together with the
// analytics or observability profiles.
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    include: ['integration/**/*.test.ts'],
    fileParallelism: false,
    testTimeout: 180_000,
    hookTimeout: 120_000,
  },
});
