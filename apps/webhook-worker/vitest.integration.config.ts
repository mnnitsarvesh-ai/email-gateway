import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// Same .env as docker compose (host ports, credentials). Values are never printed.
const envFile = resolve(__dirname, '../../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

// webhook-worker integration tests (step 6.2 §10.3, WP2): real MySQL writer, Redis and RabbitMQ
// (a throwaway vhost with the full topology) from .env, an in-process HTTPS receiver reached
// through the WEBHOOK_TEST_DIAL_MAP / WEBHOOK_TEST_ALLOW_CIDRS seams; never the public Internet.
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    include: ['integration/**/*.test.ts'],
    // Pauses a live webhook-worker and event-relay (container or host) while the suite runs.
    globalSetup: ['integration/support/live-worker.ts'],
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 120_000,
  },
});
