import { defineConfig } from 'vitest/config';

// Unit, corpus and model:check suites (no infrastructure, no network: the LLM provider runs
// against an injected fake fetch).
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    testTimeout: 60_000,
    hookTimeout: 30_000,
  },
});
