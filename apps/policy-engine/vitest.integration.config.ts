import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// Same .env as docker compose (host ports, credentials). Values are never printed.
const envFile = resolve(__dirname, '../../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

// policy-engine integration tests (step 5.2 §9.2): the evaluation in-process against the real
// MySQL writer, MinIO and a throwaway RabbitMQ vhost. Fixtures live in it-pe-* organizations.
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    include: ['integration/**/*.test.ts'],
    // Pauses the live event-relay and policy-engine while these in-process suites run.
    globalSetup: ['integration/support/live-worker.ts'],
    fileParallelism: false,
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
