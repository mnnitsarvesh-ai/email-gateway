import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// In-process API integration tests against the Compose infrastructure (MySQL, Redis, Postfix).
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    include: ['integration/**/*.test.ts'],
    setupFiles: ['integration/support/setup.ts'],
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
