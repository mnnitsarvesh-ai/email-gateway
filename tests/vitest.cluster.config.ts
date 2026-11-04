import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { defineConfig } from 'vitest/config';

// The broker node-failure test (step 3.2 §10, tests/integration/cluster/): needs the TEST-ONLY
// `rabbitmq-cluster` Compose profile, so it never runs as part of `test:integration`. Procedure:
// the header of integration/cluster/node-failure.test.ts and docs/runbooks/rabbitmq-messaging.md.
const envFile = resolve(__dirname, '../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

export default defineConfig({
  test: {
    include: ['integration/cluster/**/*.test.ts'],
    testTimeout: 900_000,
    hookTimeout: 180_000,
    fileParallelism: false,
  },
});
