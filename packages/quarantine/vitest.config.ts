import { defineConfig } from 'vitest/config';

// Unit suites only (no infrastructure): the entry state machine, reason tables, settings,
// expiry, release re-validation, separation of duties, self-service, object disposal, bulk
// limits, download tokens, digest windows (time zones, DST) and the DTO schemas.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    testTimeout: 60_000,
  },
});
