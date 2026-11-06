import { EventEmitter } from 'node:events';
import { createLogger } from '@email-gateway/logger';
import type { Browser, LaunchOptions } from 'playwright-core';
import { describe, expect, it } from 'vitest';
import { BrowserPool, browserEnvironment } from './browser-pool';

class FakeBrowser extends EventEmitter {
  closed = false;
  version(): string {
    return '156.0.0.0';
  }
  isConnected(): boolean {
    return !this.closed;
  }
  close(): Promise<void> {
    this.closed = true;
    this.emit('disconnected');
    return Promise.resolve();
  }
}

function pool(options: { sandbox?: boolean; maxJobs?: number; rss?: number | null } = {}) {
  const launches: LaunchOptions[] = [];
  const browsers: FakeBrowser[] = [];
  const restarts: string[] = [];
  const p = new BrowserPool({
    proxyUrl: 'http://url-egress-proxy:3128',
    proxyToken: 't'.repeat(32),
    maxJobs: options.maxJobs ?? 2,
    maxRssBytes: 1000,
    logger: createLogger({ service: 'test', level: 'fatal' }),
    onRestart: (reason) => restarts.push(reason),
    rss: () => options.rss ?? null,
    launch: (o) => {
      launches.push(o);
      if (o.chromiumSandbox && options.sandbox === false)
        return Promise.reject(new Error('No usable sandbox!'));
      const b = new FakeBrowser();
      browsers.push(b);
      return Promise.resolve(b as unknown as Browser);
    },
  });
  return { p, launches, browsers, restarts };
}

describe('BrowserPool', () => {
  it('probes the sandbox and falls back to chromiumSandbox=false (reported in readiness)', async () => {
    const { p, launches } = pool({ sandbox: false });
    const details = await p.checkHealth();
    expect(launches.map((l) => l.chromiumSandbox)).toEqual([true, false]);
    expect(details).toMatchObject({ chromiumSandbox: false, browserVersion: '156.0.0.0' });
    expect(launches[1]?.proxy).toEqual({
      server: 'http://url-egress-proxy:3128',
      username: 'eg',
      password: 't'.repeat(32),
    });
    expect(launches[1]?.env).toEqual(browserEnvironment());
    expect(JSON.stringify(launches[1]?.env)).not.toMatch(/amqp|TOKEN|DATABASE/i);
  });

  it('uses the sandbox when available', async () => {
    const { p } = pool({ sandbox: true });
    expect(await p.checkHealth()).toMatchObject({ chromiumSandbox: true });
  });

  it('restarts after max jobs', async () => {
    const { p, browsers, restarts } = pool({ maxJobs: 2 });
    for (let i = 0; i < 3; i += 1) await p.run(() => Promise.resolve());
    expect(restarts).toEqual(['max_jobs']);
    expect(browsers).toHaveLength(2);
    expect(browsers[0]?.closed).toBe(true);
  });

  it('restarts after a crash/disconnect and above the RSS limit', async () => {
    const crash = pool({ maxJobs: 100 });
    await crash.p.run(() => Promise.resolve());
    crash.browsers[0]?.emit('disconnected');
    await crash.p.run(() => Promise.resolve());
    expect(crash.restarts).toEqual(['crash']);

    const rss = pool({ maxJobs: 100, rss: 5000 });
    await rss.p.run(() => Promise.resolve());
    await rss.p.run(() => Promise.resolve());
    expect(rss.restarts).toEqual(['rss']);
  });

  it('a restart waits until running jobs are done', async () => {
    const { p, browsers } = pool({ maxJobs: 1 });
    let release: () => void = () => undefined;
    const first = p.run(() => new Promise<void>((r) => (release = r)));
    await new Promise((r) => setTimeout(r, 5));
    const finishedFirst = first.then(() => browsers[0]?.closed);
    release();
    expect(await finishedFirst).toBe(false);
    await p.run(() => Promise.resolve());
    expect(browsers[0]?.closed).toBe(true);
  });
});
