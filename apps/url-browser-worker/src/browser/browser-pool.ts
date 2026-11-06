import type { Logger } from '@email-gateway/logger';
import type { HealthDetails } from '@email-gateway/shared-types';
import { chromium, type Browser, type LaunchOptions } from 'playwright-core';
import { chromiumArgs } from './chromium-args';
import { descendantRssBytes } from './process-tree';
import { restartReason, type RestartReason } from './restart-policy';

export interface BrowserPoolOptions {
  proxyUrl: string;
  proxyToken: string;
  maxJobs: number;
  maxRssBytes: number;
  executablePath?: string | undefined;
  logger: Logger;
  onRestart?: (reason: RestartReason) => void;
  onRss?: (bytes: number) => void;
  /** Tests: replaces `chromium.launch`. */
  launch?: (options: LaunchOptions) => Promise<Browser>;
  /** Tests: replaces the /proc reader. */
  rss?: () => number | null;
}

/** Environment of the Chromium process: nothing of the worker's (no broker URL, no token). */
export function browserEnvironment(env: NodeJS.ProcessEnv = process.env): Record<string, string> {
  return {
    PATH: env.PATH ?? '/usr/local/bin:/usr/bin:/bin',
    HOME: '/tmp',
    TMPDIR: '/tmp',
    LANG: 'C.UTF-8',
  };
}

/**
 * One headless Chromium (Playwright's chromium-headless-shell) behind the egress proxy (U15).
 * Restarted between jobs after URL_BROWSER_MAX_JOBS_PER_BROWSER jobs, after a crash/disconnect
 * and when the process tree RSS exceeds URL_BROWSER_MAX_RSS_MB; a restart waits until no job is
 * running. Chromium's own sandbox is used when the kernel allows it (probed at the first launch),
 * else `chromiumSandbox: false` with the container controls — reported in readiness details.
 */
export class BrowserPool {
  readonly healthName = 'browser';
  private browser: Browser | null = null;
  private launching: Promise<Browser> | null = null;
  private connected = false;
  private jobsSinceLaunch = 0;
  private active = 0;
  private pendingRestart: RestartReason | null = null;
  private idleWaiters: Array<() => void> = [];
  private sandbox: boolean | null = null;
  private versionText: string | null = null;
  private lastLaunchFailed = false;
  private closed = false;
  private readonly proxy: { server: string; username: string; password: string };
  private readonly args: string[];

  constructor(private readonly options: BrowserPoolOptions) {
    const proxyUrl = new URL(options.proxyUrl);
    this.proxy = {
      server: `${proxyUrl.protocol}//${proxyUrl.host}`,
      username: 'eg',
      password: options.proxyToken,
    };
    this.args = chromiumArgs(proxyUrl.hostname);
  }

  get proxySettings(): { server: string; username: string; password: string } {
    return this.proxy;
  }

  get browserVersion(): string | null {
    return this.versionText;
  }

  get chromiumSandbox(): boolean | null {
    return this.sandbox;
  }

  /** Runs `job` with the current browser (launching or restarting it first when needed). */
  async run<T>(job: (browser: Browser) => Promise<T>): Promise<T> {
    const browser = await this.acquire();
    this.active += 1;
    try {
      return await job(browser);
    } finally {
      this.active -= 1;
      this.jobsSinceLaunch += 1;
      this.evaluate();
      if (this.active === 0) this.wakeIdle();
    }
  }

  /** Marks the browser as crashed (a page/browser crash seen by a job). */
  markCrashed(): void {
    this.connected = false;
  }

  private evaluate(): void {
    if (this.pendingRestart) return;
    const rss = (this.options.rss ?? descendantRssBytes)();
    if (rss !== null) this.options.onRss?.(rss);
    this.pendingRestart = restartReason({
      connected: this.connected,
      jobsSinceLaunch: this.jobsSinceLaunch,
      maxJobs: this.options.maxJobs,
      rssBytes: rss,
      maxRssBytes: this.options.maxRssBytes,
    });
  }

  private wakeIdle(): void {
    const waiters = this.idleWaiters;
    this.idleWaiters = [];
    for (const wake of waiters) wake();
  }

  private async acquire(): Promise<Browser> {
    if (this.closed) throw new Error('browser pool closed');
    if (!this.pendingRestart && this.browser && !this.connected) this.pendingRestart = 'crash';
    while (this.pendingRestart && this.active > 0) {
      await new Promise<void>((resolve) => this.idleWaiters.push(resolve));
    }
    if (this.pendingRestart) {
      const reason = this.pendingRestart;
      this.pendingRestart = null;
      await this.restart(reason);
    }
    if (this.browser && this.connected) return this.browser;
    return this.launch();
  }

  private async restart(reason: RestartReason): Promise<void> {
    this.options.onRestart?.(reason);
    this.options.logger.info({ reason, jobs: this.jobsSinceLaunch }, 'restarting browser');
    const old = this.browser;
    this.browser = null;
    this.connected = false;
    if (old) await old.close().catch(() => undefined);
  }

  /** Launches (once at a time); probes the Chromium sandbox at the first launch. */
  launch(): Promise<Browser> {
    this.launching ??= this.doLaunch().finally(() => {
      this.launching = null;
    });
    return this.launching;
  }

  private async doLaunch(): Promise<Browser> {
    const launch = this.options.launch ?? ((o: LaunchOptions) => chromium.launch(o));
    const base: LaunchOptions = {
      headless: true,
      args: this.args,
      proxy: this.proxy,
      env: browserEnvironment(),
      timeout: 30_000,
      handleSIGINT: false,
      handleSIGTERM: false,
      handleSIGHUP: false,
      ...(this.options.executablePath ? { executablePath: this.options.executablePath } : {}),
    };
    let browser: Browser;
    try {
      if (this.sandbox === null) {
        try {
          browser = await launch({ ...base, chromiumSandbox: true });
          this.sandbox = true;
        } catch {
          this.options.logger.warn(
            'Chromium sandbox unavailable (no unprivileged user namespaces); using chromiumSandbox=false with the container controls',
          );
          browser = await launch({ ...base, chromiumSandbox: false });
          this.sandbox = false;
        }
      } else {
        browser = await launch({ ...base, chromiumSandbox: this.sandbox });
      }
    } catch (error) {
      this.lastLaunchFailed = true;
      this.options.onRestart?.('launch_failed');
      this.options.logger.error(
        { errName: error instanceof Error ? error.name : typeof error },
        'browser launch failed',
      );
      throw error;
    }
    this.lastLaunchFailed = false;
    this.browser = browser;
    this.connected = true;
    this.jobsSinceLaunch = 0;
    this.versionText = browser.version();
    browser.on('disconnected', () => {
      if (this.browser === browser) this.connected = false;
    });
    this.options.logger.info(
      { browserVersion: this.versionText, chromiumSandbox: this.sandbox },
      'browser launched',
    );
    return browser;
  }

  /** Readiness: a browser was launched (or can be); details carry the sandbox mode. */
  async checkHealth(): Promise<HealthDetails> {
    if (this.closed) throw new Error('browser pool closed');
    if (!this.browser || !this.connected) {
      if (this.active === 0 && !this.launching) await this.launch();
      else if (this.lastLaunchFailed) throw new Error('browser launch failed');
    }
    return {
      chromiumSandbox: this.sandbox ?? false,
      browserVersion: this.versionText ?? 'unknown',
      jobsSinceLaunch: this.jobsSinceLaunch,
    };
  }

  async close(): Promise<void> {
    this.closed = true;
    const browser = this.browser;
    this.browser = null;
    this.connected = false;
    if (browser) await browser.close().catch(() => undefined);
  }
}
