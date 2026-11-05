import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { defineConfig } from 'vitest/config';

// Same .env as docker compose (CLAMAV_HOST_PORT). Values are never printed.
const envFile = resolve(__dirname, '../../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

// The real clamd of the Compose stack (clamav/clamav-debian:1.4) on 127.0.0.1:${CLAMAV_HOST_PORT}:
// PING, VERSION, INSTREAM inside IDSESSION with generated EICAR files (never committed).
export default defineConfig({
  test: {
    include: ['integration/**/*.test.ts'],
    fileParallelism: false,
    testTimeout: 120_000,
    hookTimeout: 60_000,
  },
});
