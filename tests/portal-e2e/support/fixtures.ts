/**
 * The shared test fixture of every spec:
 *
 * - **Origin guard:** every request of every page is routed; anything whose origin is not the
 *   portal (http://localhost:3001) is aborted and recorded, and the test fails at teardown. The
 *   browser therefore never reaches the api directly, a CDN, a font host or the internet.
 * - **CSP:** `securitypolicyviolation` events and CSP console errors are collected; any fails
 *   the test. Uncaught page errors fail it too.
 * - **Client address:** each test sends its own `X-Forwarded-For` from the documentation
 *   ranges. Locally the portal runs with `PORTAL_TRUST_PROXY_HOPS=0` (allowed only for
 *   `APP_ENV=local|ci`), so the BFF forwards that address through the trusted forwarder
 *   (ADR-0060) and each test gets its own per-IP login budget at the api, as distinct browsers
 *   would in production.
 */
import { createHash } from 'node:crypto';
import { test as base, expect, type BrowserContext, type Page } from '@playwright/test';
import { PORTAL_ORIGIN } from './env';

export interface Guard {
  blocked: string[];
  csp: string[];
  pageErrors: string[];
}

export function newGuard(): Guard {
  return { blocked: [], csp: [], pageErrors: [] };
}

/** A documentation-range address (RFC 5737) derived from a seed string. */
export function clientIp(seed: string): string {
  const digest = createHash('sha256').update(seed).digest();
  const net = digest[0]! % 2 === 0 ? '198.51.100' : '203.0.113';
  return `${net}.${(digest[1]! % 250) + 2}`;
}

function watchPage(page: Page, guard: Guard): void {
  page.on('console', (message) => {
    const text = message.text();
    if (/\[csp-violation\]|Content Security Policy/i.test(text)) guard.csp.push(text);
  });
  page.on('pageerror', (error) => guard.pageErrors.push(error.message));
}

/** Applies the guard, the CSP listener and the client address to a browser context. */
export async function protectContext(
  context: BrowserContext,
  guard: Guard,
  ip: string,
): Promise<void> {
  await context.setExtraHTTPHeaders({ 'x-forwarded-for': ip });
  await context.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (event) => {
      // Runs in the page: reported through the console listener above.
      // eslint-disable-next-line no-console
      console.error(
        `[csp-violation] ${event.violatedDirective} ${event.blockedURI || '(inline)'} ${event.sourceFile}:${event.lineNumber}`,
      );
    });
  });
  await context.route('**/*', async (route) => {
    const url = route.request().url();
    let origin = '';
    try {
      origin = new URL(url).origin;
    } catch {
      origin = '';
    }
    if (origin !== PORTAL_ORIGIN) {
      guard.blocked.push(url);
      await route.abort('blockedbyclient');
      return;
    }
    await route.continue();
  });
  context.on('page', (page) => watchPage(page, guard));
  for (const page of context.pages()) watchPage(page, guard);
}

export function assertGuardClean(guard: Guard): void {
  expect(guard.blocked, 'requests to an origin other than the portal').toEqual([]);
  expect(guard.csp, 'CSP violations').toEqual([]);
  expect(guard.pageErrors, 'uncaught page errors').toEqual([]);
}

export const test = base.extend<{ guard: Guard; forwardedIp: string }>({
  // Playwright requires the destructuring pattern for fixtures without dependencies.
  // eslint-disable-next-line no-empty-pattern
  forwardedIp: async ({}, use, testInfo) => {
    await use(clientIp(`${testInfo.testId}:${testInfo.retry}:${testInfo.project.name}`));
  },
  // eslint-disable-next-line no-empty-pattern
  guard: async ({}, use) => {
    await use(newGuard());
  },
  context: async ({ context, guard, forwardedIp }, use) => {
    await protectContext(context, guard, forwardedIp);
    await use(context);
    assertGuardClean(guard);
  },
});

export { expect };
