import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// Same .env as docker compose (host ports, credentials). Values are never printed.
const envFile = resolve(__dirname, '../../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

// archive-worker integration tests (step 8.1 §9.2, WP3): the real MySQL writer, MinIO (the
// lock-enabled archive bucket and the TEST-ONLY replica bucket), OpenSearch (a per-run index
// prefix) and RabbitMQ (a throwaway vhost with the full topology). Every job runs in-process,
// restricted to the suite's own organizations, with per-run lock and cursor names.
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    include: ['integration/**/*.test.ts'],
    // Pauses a live archive-worker (container or host) while the suite runs.
    globalSetup: ['integration/support/live-worker.ts'],
    fileParallelism: false,
    testTimeout: 120_000,
    hookTimeout: 180_000,
  },
});
