import { defineConfig } from 'vitest/config';

// Unit and property suites only (no infrastructure): schema refusals, operators, Kleene logic,
// conflict resolution, the strictness floor, time zones, determinism (seeded property test),
// ReDoS bounds, the input builder (fixtures from @email-gateway/risk-scoring) and the DSL
// reference examples.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    testTimeout: 120_000,
  },
});
