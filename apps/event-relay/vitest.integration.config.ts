import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// Same .env as docker compose (host ports, credentials). Values are never printed.
const envFile = resolve(__dirname, '../../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

// event-relay integration tests: real MySQL writer and RabbitMQ from .env. Each suite works in a
// throwaway vhost `eg-it-<hex>` with the full topology and in it-* fixture organizations; the
// in-process relay and reconciler are scoped to those organizations.
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    include: ['integration/**/*.test.ts'],
    // Pauses a live event-relay and the outbox-polling workers while these suites run.
    globalSetup: ['integration/support/live-relay.ts'],
    fileParallelism: false,
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
