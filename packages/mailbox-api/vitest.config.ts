import { defineConfig } from 'vitest/config';

// Unit suites only (no infrastructure): the pure helpers, the raw extractor and the clients
// running against the in-process provider simulators of `@email-gateway/idp-adapters/testing` on
// 127.0.0.1. No real provider endpoint is ever called.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    testTimeout: 60_000,
  },
});
