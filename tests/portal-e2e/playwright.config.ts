/**
 * Playwright configuration of the admin portal end-to-end tests (step 7.1 WP6, design §9).
 *
 * - Chromium only, from the pinned Playwright 1.64.1 browser cache (installed once with
 *   `pnpm --filter @email-gateway/portal-e2e browsers:install`); the test script sets
 *   PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 and the global setup fails when the browser is missing.
 * - The portal (`next start` on 3001) and the api (host, 3200) must be running; see
 *   docs/frontend/running-and-testing.md.
 * - One worker: the specs share one seeded data set and enroll MFA once per run.
 */
import { defineConfig, devices } from '@playwright/test';
import { PORTAL_ORIGIN } from './support/env';

const shared = {
  baseURL: PORTAL_ORIGIN,
  browserName: 'chromium' as const,
  locale: 'en-US',
  timezoneId: 'UTC',
  serviceWorkers: 'block' as const,
  trace: 'retain-on-failure' as const,
  screenshot: 'only-on-failure' as const,
  video: 'off' as const,
};

export default defineConfig({
  testDir: './specs',
  globalSetup: './global-setup.ts',
  globalTeardown: './global-teardown.ts',
  fullyParallel: false,
  workers: 1,
  retries: 1,
  forbidOnly: true,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  outputDir: 'test-results',
  reporter: [['list'], ['html', { open: 'never', outputFolder: 'playwright-report' }]],
  projects: [
    {
      // Every spec; responsive.spec also runs in the two emulated devices below.
      name: 'desktop',
      use: { ...devices['Desktop Chrome'], ...shared, viewport: { width: 1440, height: 900 } },
    },
    {
      name: 'tablet',
      testMatch: /responsive\.spec\.ts/,
      use: {
        ...devices['iPad Pro 11'],
        ...shared,
        viewport: { width: 834, height: 1112 },
        isMobile: true,
        hasTouch: true,
      },
    },
    {
      name: 'mobile',
      testMatch: /responsive\.spec\.ts/,
      use: {
        ...devices['iPhone 13'],
        ...shared,
        viewport: { width: 390, height: 844 },
        isMobile: true,
        hasTouch: true,
      },
    },
  ],
});
