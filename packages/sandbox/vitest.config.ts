import { defineConfig } from 'vitest/config';

// Unit suites only (no infrastructure): envelopes, keys, result MAC, analysis key, verdict map.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    testTimeout: 30_000,
  },
});
