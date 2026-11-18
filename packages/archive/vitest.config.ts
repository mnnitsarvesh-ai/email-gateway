import { defineConfig } from 'vitest/config';

// Unit suites only (no infrastructure): key wrapping and the archive-object/1 streams, the JSON
// documents, capture and journal eligibility, retention and expiry, legal-hold matching, the
// OpenSearch template and builders, the snapshot codec, object keys, download tokens and exports.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    testTimeout: 120_000,
  },
});
