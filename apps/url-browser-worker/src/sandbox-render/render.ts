import { createHash } from 'node:crypto';
import type {
  Browser,
  Download,
  Dialog,
  Frame,
  LaunchOptions,
  Page,
  Request,
} from 'playwright-core';
import { chromiumArgs, CONTEXT_OPTIONS } from '../browser/chromium-args';
import type { RenderHeader } from './frame';

/**
 * Browser rendering of one sandbox sample (step 4.6 X6 `browser` profile). Runs inside a
 * disposable hardened runner container started by the sandbox-controller from this image
 * (LOCAL/CI ONLY, NOT A VM BOUNDARY): user 65532, read-only root, tmpfs /scratch, no
 * capabilities, the internal detonation network whose only peer is the recording sinkhole.
 *
 * Chromium headless shell with the url-browser-worker's hardening flags but WITHOUT the egress
 * proxy and WITHOUT the host-resolver map: names resolve through the container resolver (the
 * sinkhole), so the sinkhole records every host the page asks for and nothing leaves the
 * detonation network. The sample is loaded from `file://` with JavaScript on; downloads are
 * cancelled and counted, dialogs dismissed and counted; after `min(wall − 5 s, 15 s)` one PNG
 * screenshot (1280×800) is taken and the request hosts, form and password-field counts are
 * reported. Nothing here reads the url-browser-worker's configuration or broker settings.
 */

export const RENDER_VERSION = 'sandbox-render/1';
export const MAX_WAIT_MS = 15_000;
export const MAX_REQUEST_LIST = 50;
const SCREENSHOT_TIMEOUT_MS = 10_000;

export interface RenderReport {
  v: 1;
  mode: 'browser';
  error: string | null;
  durationMs: number;
  navigations: number;
  requests: number;
  requestList: Array<{
    host: string;
    port: number;
    method: 'GET' | 'POST' | 'HEAD' | 'PUT' | 'OTHER';
    pathSha256: string;
    scheme: 'http' | 'https' | 'ws' | 'wss' | 'other';
  }>;
  downloadsAttempted: number;
  dialogs: number;
  passwordFields: number;
  forms: number;
  crossOriginForms: number;
  jsRedirects: number;
  screenshot: boolean;
  chromiumVersion: string | null;
}

export interface RenderResult {
  report: RenderReport;
  screenshot: Buffer | null;
}

export interface RenderDeps {
  launch: (options: LaunchOptions) => Promise<Browser>;
  /** Writes the sample; returns its file:// URL. */
  writeSample: (sample: Buffer, detectedType: 'html' | 'svg') => string;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

/** Chromium flags: the url-browser-worker's set minus the proxy-only resolver map. */
export function renderChromiumArgs(): string[] {
  return [
    ...chromiumArgs('localhost').filter((arg) => !arg.startsWith('--host-resolver-rules=')),
    '--no-proxy-server',
  ];
}

/** Chromium's environment: nothing of the runner's (scratch home/tmp only). */
export function renderEnvironment(): Record<string, string> {
  return {
    PATH: '/usr/local/bin:/usr/bin:/bin',
    HOME: '/scratch/home',
    TMPDIR: '/scratch/tmp',
    LANG: 'C.UTF-8',
  };
}

const METHODS = new Set(['GET', 'POST', 'HEAD', 'PUT']);

/** A request summary for the report (no paths: their SHA-256 only), or null for local schemes. */
export function summarizeRequest(
  url: string,
  method: string,
): RenderReport['requestList'][number] | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  const protocol = parsed.protocol.replace(/:$/, '');
  if (
    ['file', 'data', 'blob', 'about', 'chrome', 'chrome-extension', 'javascript'].includes(protocol)
  ) {
    return null;
  }
  const scheme = (['http', 'https', 'ws', 'wss'] as const).find((s) => s === protocol) ?? 'other';
  const defaultPort = scheme === 'https' || scheme === 'wss' ? 443 : 80;
  const port = parsed.port ? Number(parsed.port) : defaultPort;
  const host = parsed.hostname.toLowerCase().slice(0, 253);
  if (host.length === 0 || !Number.isInteger(port) || port < 1 || port > 65_535) return null;
  return {
    host,
    port,
    method: (METHODS.has(method)
      ? method
      : 'OTHER') as RenderReport['requestList'][number]['method'],
    pathSha256: createHash('sha256').update(`${parsed.pathname}${parsed.search}`).digest('hex'),
    scheme,
  };
}

/** True for a form action that leaves the sample's own (file://) origin. */
export function isCrossOriginAction(action: string): boolean {
  try {
    const url = new URL(action);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

export function emptyReport(error: string | null): RenderReport {
  return {
    v: 1,
    mode: 'browser',
    error,
    durationMs: 0,
    navigations: 0,
    requests: 0,
    requestList: [],
    downloadsAttempted: 0,
    dialogs: 0,
    passwordFields: 0,
    forms: 0,
    crossOriginForms: 0,
    jsRedirects: 0,
    screenshot: false,
    chromiumVersion: null,
  };
}

/** Renders one sample within `wallTimeoutMs − 2 s`; never throws for a property of the page. */
export async function renderSample(
  header: RenderHeader,
  sample: Buffer,
  deps: RenderDeps,
): Promise<RenderResult> {
  const now = deps.now ?? Date.now;
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const started = now();
  const deadline = started + header.wallTimeoutMs - 2_000;
  const remaining = () => Math.max(0, deadline - now());
  const report = emptyReport(null);
  const seen = new Set<string>();
  let screenshot: Buffer | null = null;
  let browser: Browser | null = null;
  try {
    const url = deps.writeSample(sample, header.detectedType);
    try {
      browser = await deps.launch({
        headless: true,
        args: renderChromiumArgs(),
        env: renderEnvironment(),
        chromiumSandbox: false,
        timeout: Math.max(1_000, Math.min(30_000, remaining() - 3_000)),
        handleSIGINT: false,
        handleSIGTERM: false,
        handleSIGHUP: false,
      });
    } catch {
      report.error = 'launch_failed';
      return { report, screenshot };
    }
    report.chromiumVersion = browser.version().slice(0, 64);
    const context = await browser.newContext({
      ...CONTEXT_OPTIONS,
      acceptDownloads: false,
      viewport: { width: 1280, height: 800 },
    });
    const page: Page = await context.newPage();
    page.on('request', (request: Request) => {
      report.requests += 1;
      const summary = summarizeRequest(request.url(), request.method());
      if (!summary || report.requestList.length >= MAX_REQUEST_LIST) return;
      const key = `${summary.scheme}|${summary.host}|${summary.port}|${summary.method}|${summary.pathSha256}`;
      if (seen.has(key)) return;
      seen.add(key);
      report.requestList.push(summary);
    });
    page.on('download', (download: Download) => {
      report.downloadsAttempted += 1;
      download.cancel().catch(() => undefined);
    });
    page.on('dialog', (dialog: Dialog) => {
      report.dialogs += 1;
      dialog.dismiss().catch(() => undefined);
    });
    page.on('framenavigated', (frame: Frame) => {
      if (frame === page.mainFrame()) report.navigations += 1;
    });

    try {
      await page.goto(url, { waitUntil: 'load', timeout: Math.max(1_000, remaining() - 4_000) });
    } catch {
      report.error = 'navigation_incomplete';
    }
    const wait = Math.min(header.wallTimeoutMs - 5_000, MAX_WAIT_MS, remaining() - 3_000);
    if (wait > 0) await sleep(wait);

    try {
      const dom = await page.evaluate(() => ({
        passwordFields: document.querySelectorAll('input[type="password" i]').length,
        forms: document.forms.length,
        actions: Array.from(document.forms)
          .slice(0, 64)
          .map((form) => form.action),
      }));
      report.passwordFields = Math.min(dom.passwordFields, 1_000_000);
      report.forms = Math.min(dom.forms, 1_000_000);
      report.crossOriginForms = dom.actions.filter(
        (a) => typeof a === 'string' && isCrossOriginAction(a),
      ).length;
    } catch {
      report.error ??= 'dom_unavailable';
    }
    report.jsRedirects = Math.max(0, report.navigations - 1);

    if (header.maxArtifacts >= 1 && remaining() > 1_000) {
      try {
        const png = await page.screenshot({
          type: 'png',
          fullPage: false,
          timeout: Math.min(SCREENSHOT_TIMEOUT_MS, remaining() - 500),
        });
        if (png.length <= header.maxArtifactBytes && png.length <= header.maxTotalArtifactBytes) {
          screenshot = png;
          report.screenshot = true;
        }
      } catch {
        report.error ??= 'screenshot_failed';
      }
    }
    return { report, screenshot };
  } finally {
    report.durationMs = Math.max(0, now() - started);
    if (browser) await browser.close().catch(() => undefined);
  }
}
