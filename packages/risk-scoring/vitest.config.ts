import { defineConfig } from 'vitest/config';

// Unit suites only (no infrastructure): signal map, groups, failures, hard blocks, trust,
// profiles, determinism (seeded property test), explanation, row mapping, and the
// dataset:check / calibrate:check comparisons of the committed artifacts.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    testTimeout: 60_000,
  },
});
