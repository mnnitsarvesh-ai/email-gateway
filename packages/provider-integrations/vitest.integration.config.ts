import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { defineConfig } from 'vitest/config';

// Same .env as docker compose (host ports, credentials). Values are never printed.
const envFile = resolve(__dirname, '../../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

// Grant store and connection reader against the real MySQL writer (step 8.2 §10.1; synthetic
// `it-prov-*` organizations, never an existing organization), provider calls against the
// in-process fake only.
export default defineConfig({
  test: {
    include: ['integration/**/*.test.ts'],
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
