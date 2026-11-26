import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// Same .env as docker compose (host ports, credentials). Values are never printed.
const envFile = resolve(__dirname, '../../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

// mailbox-worker integration tests (step API-1 §9.3, WP3): the real MySQL writer, Redis, MinIO and
// (copies over the broker) a throwaway RabbitMQ vhost with the full topology; the in-process
// provider simulators of @email-gateway/idp-adapters (Graph, Gmail, Google Directory on 127.0.0.1)
// and an injected clock. Every suite creates its own `it-apimode-` organizations, restricts the
// worker to them and removes everything afterwards. Nothing reaches a real provider.
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    include: ['integration/**/*.test.ts'],
    fileParallelism: false,
    testTimeout: 180_000,
    hookTimeout: 180_000,
  },
});
