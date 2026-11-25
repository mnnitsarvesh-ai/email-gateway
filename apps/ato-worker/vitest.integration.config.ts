import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// Same .env as docker compose (host ports, credentials). Values are never printed.
const envFile = resolve(__dirname, '../../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

// ato-worker integration tests (step 8.4 §10.3, WP4): the real MySQL writer, Redis and RabbitMQ
// (a throwaway vhost with the full topology), the synthetic GeoIP databases (documentation ranges),
// the fake identity provider and an injected clock. Every suite creates its own `it-ato-`
// organizations, restricts the worker to them, and removes everything afterwards.
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    include: ['integration/**/*.test.ts'],
    // Pauses a live ato-worker (container or host) while the suites run, and afterwards removes
    // the platform-wide IP windows and campaign flags of the documentation ranges the suites used.
    globalSetup: ['integration/support/live-worker.ts', 'integration/support/ip-windows.ts'],
    fileParallelism: false,
    testTimeout: 600_000,
    hookTimeout: 600_000,
  },
});
