import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// Same .env as docker compose (host ports, credentials). Values are never printed.
const envFile = resolve(__dirname, '../../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

// email-worker integration tests (step 3.1 §9): the MIME ingestion stage in-process against the
// real MySQL writer, MinIO and Redis from .env. Fixtures live in it-mime-* organizations.
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    include: ['integration/**/*.test.ts'],
    // Pauses a live email-worker (container or host) while these in-process suites run.
    globalSetup: ['integration/support/live-worker.ts'],
    fileParallelism: false,
    // The large-message test measures live memory after forced collections.
    pool: 'forks',
    poolOptions: { forks: { execArgv: ['--expose-gc'] } },
    testTimeout: 180_000,
    hookTimeout: 120_000,
  },
});
