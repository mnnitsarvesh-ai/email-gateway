import { defineConfig } from 'vitest/config';

// Unit suites only (no infrastructure): the event catalogue and data schemas, envelopes and
// deterministic ids, filters, signatures, the secret cipher, retry schedules, the payload guard,
// response snippets and the notification settings.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    testTimeout: 60_000,
  },
});
