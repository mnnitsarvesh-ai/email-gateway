import { defineConfig } from 'vitest/config';

// Own config so vitest does not pick up tests/vitest.config.ts (the stack suites) from the parent.
export default defineConfig({
  test: { include: ['**/*.test.ts'], testTimeout: 60_000 },
});
