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
    testTimeout: 20_000,
    // Server modules run under node; they declare `// @vitest-environment node` themselves.
    restoreMocks: true,
  },
});
