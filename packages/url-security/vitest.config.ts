import { defineConfig } from 'vitest/config';

// Unit tests (no infrastructure): in-process HTTP/HTTPS/proxy/DNS servers only.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
