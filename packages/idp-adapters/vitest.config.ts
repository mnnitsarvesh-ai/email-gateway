import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const atoDetection = (path: string) =>
  fileURLToPath(new URL(`../ato-detection/src/${path}`, import.meta.url));

// Unit suites only (no infrastructure): the core (HTTP client, cursors, windows, traits,
// snapshots, capabilities, settings, configuration), the in-process provider simulators and the
// adapters running against them on 127.0.0.1, the 8.4 contract kit and the 8.2 bindings. No real
// provider endpoint is ever called.
//
// `@email-gateway/ato-detection` resolves to its TypeScript sources under Vitest: its test kit
// (`/testing`, the 8.4 contract kit) imports Vitest, which cannot be required from the compiled
// CommonJS, and the runtime entry must be the same module instance as the kit's (the kit checks
// `instanceof ProviderAdapterError`).
export default defineConfig({
  resolve: {
    alias: [
      {
        find: /^@email-gateway\/ato-detection\/testing$/,
        replacement: atoDetection('testing/index.ts'),
      },
      { find: /^@email-gateway\/ato-detection$/, replacement: atoDetection('index.ts') },
    ],
  },
  test: {
    include: ['src/**/*.test.ts'],
    testTimeout: 60_000,
  },
});
