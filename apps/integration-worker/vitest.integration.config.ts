import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// Same .env as docker compose (host ports, credentials). Values are never printed.
const envFile = resolve(__dirname, '../../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

// integration-worker integration tests (step 8.2 §10.3, WP4): the real MySQL writer and reader,
// the in-process provider fake and an injected clock; synthetic `it-prov-*` organizations only.
// No real Microsoft or Google endpoint is ever contacted.
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    include: ['integration/**/*.test.ts'],
    // Pauses a live integration-worker and event-relay while these suites run.
    globalSetup: ['integration/support/live-workers.ts'],
    fileParallelism: false,
    testTimeout: 120_000,
    hookTimeout: 180_000,
  },
});
