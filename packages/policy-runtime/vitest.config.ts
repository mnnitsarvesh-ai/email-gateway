import { defineConfig } from 'vitest/config';

// Unit suites only (no infrastructure): the writer reads of one evaluation against transaction
// doubles (echo checks, limits), the snapshot cache, the input builder, the copy-round runner
// (`evaluateCopyRound`, `policyOutcomeOf`, `detectRowData`) and the execution-log row mapping.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    testTimeout: 60_000,
  },
});
