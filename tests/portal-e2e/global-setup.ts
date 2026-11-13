/**
 * Global setup: (1) the pinned Chromium of Playwright 1.64.1 must already be in the browser
 * cache (never downloaded here); (2) the api and the portal must answer their probes; (3) the
 * synthetic tenants are (re)seeded and visible on the replica.
 */
import { existsSync } from 'node:fs';
import { chromium } from '@playwright/test';
import { seed } from './seed/seed';
import { PORTAL_ORIGIN, apiOrigin, loadEnv } from './support/env';

const INSTALL_HINT =
  'Install it once with `pnpm --filter @email-gateway/portal-e2e browsers:install` ' +
  '(the only step that downloads a browser), or run inside ' +
  'mcr.microsoft.com/playwright:v1.64.1-noble (docs/frontend/running-and-testing.md).';

async function probe(url: string, what: string): Promise<void> {
  let lastError = '';
  for (let attempt = 0; attempt < 10; attempt++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(5_000) });
      if (res.ok) return;
      lastError = `HTTP ${res.status}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await new Promise((r) => setTimeout(r, 1_000));
  }
  throw new Error(`${what} is not ready at ${url} (${lastError})`);
}

export default async function globalSetup(): Promise<void> {
  loadEnv();
  if (process.env.PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD !== '1') {
    throw new Error('Run the suite through `pnpm test` (sets PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1).');
  }
  const executable = chromium.executablePath();
  if (!executable || !existsSync(executable)) {
    throw new Error(`The pinned Chromium is not installed (${executable}). ${INSTALL_HINT}`);
  }
  await probe(`${apiOrigin()}/health/ready`, 'The api');
  await probe(`${PORTAL_ORIGIN}/api/health`, 'The admin portal');
  const summary = await seed();
  process.stdout.write(
    `portal-e2e seed: ${summary.messages} messages, ${summary.users} users, ` +
      `${summary.quarantineEntries} quarantine entries, ${summary.auditRows} audit rows ` +
      `(${summary.durationMs} ms; removed ${summary.removed.organizations} organizations)\n`,
  );
}
