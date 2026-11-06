import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { defineConfig } from 'vitest/config';

// Same .env as docker compose (DNS_SINK_HOST_PORT, URL_TEST_*_HOST_PORT). Values are never printed.
const envFile = resolve(__dirname, '../../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

// Host-run suites against the TEST-ONLY smtp-test profile (step 4.3 U19): the resolver, dnsbl
// and rdap providers query dns-sink on 127.0.0.1:${DNS_SINK_HOST_PORT}; the fetcher reaches the
// url-test container through the test dial map (203.0.113.10:80/443 -> published host ports)
// after the guard validated the resolved documentation-range address.
export default defineConfig({
  test: {
    include: ['integration/**/*.test.ts'],
    fileParallelism: false,
    testTimeout: 120_000,
    hookTimeout: 60_000,
  },
});
