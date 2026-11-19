import { defineConfig } from 'vitest/config';

// Unit suites only (no infrastructure; step 8.2 §10.1): permission profiles, the credential
// cipher, the HTTP primitive, the Microsoft and Google clients and token service against the
// in-process FakeProviderServer, health evaluation, validation, setup guides, impact tokens and
// egress imports. No real Microsoft or Google endpoint is ever contacted.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    testTimeout: 60_000,
  },
});
