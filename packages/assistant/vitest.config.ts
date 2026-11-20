import { defineConfig } from 'vitest/config';

// Unit suites only (no infrastructure, no network: every provider runs against an injected fake
// fetch with recorded synthetic fixtures).
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts', 'scripts/**/*.test.ts'],
    testTimeout: 30_000,
  },
});
