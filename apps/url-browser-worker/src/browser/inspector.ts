import type { Browser, BrowserContext, Page, Request, Response } from 'playwright-core';
import { CONTEXT_OPTIONS } from './chromium-args';
import {
  boundedSignals,
  emptySignals,
  finalUrlFields,
  formSignals,
  NavigationTracker,
  titleBrandMatches,
  type Navigation,
  type Signals,
  type TitleBrandEntry,
} from './signals';

/** Header the egress proxy sets on its own 403 (`EGRESS_BLOCKED_HEADER` of url-security). */
const BLOCKED_HEADER = 'x-egress-blocked-reason';
/** Chromium errors of a CONNECT the proxy refused (or could not open). */
const TUNNEL_ERRORS = /ERR_TUNNEL_CONNECTION_FAILED|ERR_PROXY_CONNECTION_FAILED|ERR_PROXY_AUTH/;
const MAX_FORMS_READ = 20;
const MAX_FRAMES_READ = 20;
const DOM_READ_TIMEOUT_MS = 1000;

export type InspectionErrorCode =
  | 'navigation_timeout'
  | 'proxy_refused'
  | 'browser_crash'
  | 'job_timeout'
  | 'navigation_failed'
  | 'deadline_passed'
  | 'invalid_url';

export interface InspectionOutcome {
  status: 'completed' | 'failed';
  errorCode: InspectionErrorCode | null;
  navigations: Navigation[];
  signals: Signals;
  finalUrlSha256: string | null;
  finalHost: string | null;
  durationMs: number;
  /** The browser crashed or disconnected during the job (the pool restarts it). */
  crashed: boolean;
}

export interface InspectorOptions {
  proxy: { server: string; username: string; password: string };
  navigationTimeoutMs: number;
  jobTimeoutMs: number;
  settleMs: number;
  brands: readonly TitleBrandEntry[];
}

/**
 * One dynamic inspection (U15) in a fresh incognito context: navigate, wait for `load` plus up
 * to `settleMs` of further navigations, then collect counts/booleans/hosts/brand ids. Dialogs are
 * dismissed, downloads cancelled and reported, every request goes through the egress proxy (a
 * proxy refusal counts as a blocked request). The context is always closed; the whole job is
 * bounded by URL_BROWSER_JOB_TIMEOUT_MS. DOM reads use Playwright's isolated utility world
 * (locators), never the page's own JavaScript.
 */
export async function inspectUrl(
  browser: Browser,
  url: string,
  options: InspectorOptions,
): Promise<InspectionOutcome> {
  const started = Date.now();
  const signals = emptySignals();
  const tracker = new NavigationTracker();
  let context: BrowserContext | null = null;
  let crashed = false;
  let timedOut = false;
  let errorCode: InspectionErrorCode | null = null;
  let finalUrl = url;

  const run = async (): Promise<void> => {
    context = await browser.newContext({
      ...CONTEXT_OPTIONS,
      permissions: [],
      proxy: options.proxy,
    });
    const page = await context.newPage();
    page.setDefaultNavigationTimeout(options.navigationTimeoutMs);
    page.setDefaultTimeout(options.navigationTimeoutMs);
    const navIndex = new WeakMap<Request, number>();
    const isMainNavigation = (request: Request): boolean => {
      try {
        return request.isNavigationRequest() && request.frame() === page.mainFrame();
      } catch {
        return false;
      }
    };

    page.on('dialog', (dialog) => {
      signals.dialogs += 1;
      dialog.dismiss().catch(() => undefined);
    });
    page.on('download', (download) => {
      signals.downloadAttempted = true;
      download.cancel().catch(() => undefined);
    });
    page.on('crash', () => {
      crashed = true;
    });
    page.on('load', () => {
      void hasMetaRefresh(page).then((meta) => {
        if (meta) tracker.sawMetaRefresh();
      });
    });
    context.on('request', (request) => {
      signals.requests += 1;
      if (isMainNavigation(request))
        navIndex.set(request, tracker.request(request.url(), request.redirectedFrom() !== null));
    });
    context.on('response', (response: Response) => {
      const request = response.request();
      const index = navIndex.get(request);
      if (index !== undefined && index >= 0) tracker.status(index, response.status());
      const headers = response.headers();
      if (response.status() === 403 && headers[BLOCKED_HEADER]) signals.blockedRequests += 1;
      if (
        isMainNavigation(request) &&
        /^\s*attachment/i.test(headers['content-disposition'] ?? '')
      ) {
        signals.downloadAttempted = true;
      }
    });
    context.on('requestfailed', (request) => {
      const text = request.failure()?.errorText ?? '';
      if (TUNNEL_ERRORS.test(text)) signals.blockedRequests += 1;
    });
    context.on('requestfinished', (request) => {
      request
        .sizes()
        .then((sizes) => {
          signals.bytes +=
            Math.max(0, sizes.responseBodySize) + Math.max(0, sizes.responseHeadersSize);
        })
        .catch(() => undefined);
    });

    let response: Response | null = null;
    try {
      response = await page.goto(url, { waitUntil: 'load', timeout: options.navigationTimeoutMs });
    } catch (error) {
      const message = error instanceof Error ? error.message : '';
      if (/Download is starting/i.test(message)) {
        signals.downloadAttempted = true;
      } else if (crashed || /crash/i.test(message)) {
        crashed = true;
        errorCode = 'browser_crash';
        return;
      } else if (timedOut || /has been closed/i.test(message)) {
        // The job timer closed the context (job_timeout is set by the caller) or the browser
        // went away (browser_crash, decided by the caller from isConnected()).
        throw error;
      } else if (/Timeout|timed out/i.test(message)) {
        errorCode = 'navigation_timeout';
      } else if (TUNNEL_ERRORS.test(message)) {
        errorCode = 'proxy_refused';
      } else {
        errorCode = 'navigation_failed';
      }
    }
    if (response && response.status() === 403 && response.headers()[BLOCKED_HEADER])
      errorCode = 'proxy_refused';

    if (errorCode === null) {
      // Up to settleMs of further (JS/meta) navigations; stop after 1 s of quiet.
      const settleUntil = Date.now() + options.settleMs;
      const loadedAt = Date.now();
      while (Date.now() < settleUntil) {
        await page.waitForTimeout(200);
        const quietSince = Math.max(tracker.lastAt, loadedAt);
        if (Date.now() - quietSince >= 1000) break;
      }
      await page
        .waitForLoadState('load', { timeout: Math.max(500, settleUntil - Date.now()) })
        .catch(() => undefined);
    }
    finalUrl = page.url();
    await collectDom(page, signals, options.brands, finalUrl);
  };

  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      run(),
      new Promise<void>((_, reject) => {
        timer = setTimeout(() => {
          timedOut = true;
          reject(new Error('job timeout'));
        }, options.jobTimeoutMs);
      }),
    ]);
  } catch (error) {
    if (timedOut) errorCode = 'job_timeout';
    else if (crashed || !browser.isConnected()) errorCode = 'browser_crash';
    else errorCode ??= 'navigation_failed';
    void error;
  } finally {
    clearTimeout(timer);
    const open = context as BrowserContext | null;
    if (open) await open.close().catch(() => undefined);
  }
  if (!browser.isConnected()) crashed = true;
  if (crashed && errorCode === null) errorCode = 'browser_crash';
  const final = finalUrlFields(finalUrl);
  signals.jsRedirect = tracker.jsRedirect;
  return {
    status: errorCode === null ? 'completed' : 'failed',
    errorCode,
    navigations: tracker.entries,
    signals: boundedSignals(signals),
    finalUrlSha256: final.finalUrlSha256,
    finalHost: final.finalHost,
    durationMs: Date.now() - started,
    crashed,
  };
}

async function hasMetaRefresh(page: Page): Promise<boolean> {
  try {
    return (await page.locator('meta[http-equiv="refresh" i]').count()) > 0;
  } catch {
    return false;
  }
}

/** Password fields and forms of every frame (bounded), form actions, title brand matches. */
async function collectDom(
  page: Page,
  signals: Signals,
  brands: readonly TitleBrandEntry[],
  pageUrl: string,
): Promise<void> {
  const actions: Array<string | null> = [];
  for (const frame of page.frames().slice(0, MAX_FRAMES_READ)) {
    try {
      signals.passwordFields += await frame.locator('input[type="password" i]').count();
      const forms = frame.locator('form');
      const count = await forms.count();
      signals.forms += count;
      for (
        let i = 0;
        i < Math.min(count, MAX_FORMS_READ) && actions.length < MAX_FORMS_READ;
        i += 1
      ) {
        actions.push(await forms.nth(i).getAttribute('action', { timeout: DOM_READ_TIMEOUT_MS }));
      }
    } catch {
      // A frame navigated or detached meanwhile: what was read counts.
    }
  }
  const forms = formSignals(pageUrl, actions);
  signals.crossOriginFormAction = forms.crossOriginFormAction;
  signals.formActionHosts = forms.formActionHosts;
  try {
    signals.titleBrandMatches = titleBrandMatches(await page.title(), pageUrl, brands);
  } catch {
    signals.titleBrandMatches = [];
  }
}
