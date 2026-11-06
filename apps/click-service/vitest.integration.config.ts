import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// Same .env as docker compose (CLICK_DATABASE_URL with the gateway_click account, REDIS_URL,
// URL_* keys, url-test host ports). Values are never printed.
const envFile = resolve(__dirname, '../../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

// click-service integration tests (step 4.3 §9): the app in-process against the real MySQL
// writer (click account), Redis, dns-sink and url-test (smtp-test profile, via the dial map).
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    include: ['integration/**/*.test.ts'],
    fileParallelism: false,
    testTimeout: 120_000,
    hookTimeout: 60_000,
  },
});
