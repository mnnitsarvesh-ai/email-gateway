import path from 'node:path';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
      // `server-only` throws outside the react-server condition; tests import server modules directly.
      'server-only': path.resolve(__dirname, 'src/test/server-only-stub.ts'),
    },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}', 'scripts/**/*.test.{ts,mjs}'],
    setupFiles: ['src/test/setup.ts'],
    css: false,
    // The interactive page and editor tests (full forms, several submits, axe) take 2–4 s alone,
    // but the repository's uncached parallel `pnpm test` (about ten turbo tasks, each with its own
    // workers) slows them 6–10×: step 7.3 verification saw different ones pass 20 s on each run.
    testTimeout: 60_000,
    // Server modules run under node; they declare `// @vitest-environment node` themselves.
    restoreMocks: true,
  },
});
