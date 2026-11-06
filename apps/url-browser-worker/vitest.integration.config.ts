import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// Same .env as docker compose. Values are never printed.
const envFile = resolve(__dirname, '../../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

// Focused suite (step 4.3 §9, profile url-browser): a real Chromium job through the egress proxy
// against url-test, isolation checks of the running containers. Never run with the analytics or
// observability profiles on the 8 GB VM.
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    include: ['integration/**/*.test.ts'],
    fileParallelism: false,
    testTimeout: 180_000,
    hookTimeout: 120_000,
  },
});
