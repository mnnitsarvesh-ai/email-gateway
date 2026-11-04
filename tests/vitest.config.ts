import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { defineConfig } from 'vitest/config';

// Integration tests read the same .env as docker compose (ports, credentials).
const envFile = resolve(__dirname, '../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

export default defineConfig({
  test: {
    include: ['integration/**/*.test.ts'],
    // The 3-node broker test needs the rabbitmq-cluster profile: `pnpm test:cluster` only.
    exclude: ['integration/cluster/**', '**/node_modules/**'],
    testTimeout: 20_000,
    hookTimeout: 30_000,
    fileParallelism: false,
  },
});
