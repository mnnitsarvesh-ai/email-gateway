import { defineConfig } from 'vitest/config';

// Unit suites only (no infrastructure): preview sanitization corpus, link defanging, DLP
// masking, signed/encrypted detection and streaming banner insertion on generated MIME.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    testTimeout: 60_000,
  },
});
