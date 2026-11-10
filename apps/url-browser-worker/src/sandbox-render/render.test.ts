import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Browser, LaunchOptions } from 'playwright-core';
import { describe, expect, it, vi } from 'vitest';
import type { RenderHeader } from './frame';
import {
  isCrossOriginAction,
  renderChromiumArgs,
  renderEnvironment,
  renderSample,
  summarizeRequest,
} from './render';
import { writeSampleFile } from './render-main';

const header: RenderHeader = {
  v: 1,
  taskId: 't-1',
  profile: 'browser',
  detectedType: 'html',
  wallTimeoutMs: 20_000,
  maxArtifacts: 2,
  maxArtifactBytes: 1_000_000,
  maxTotalArtifactBytes: 2_000_000,
  sampleSize: 4,
};

type Handler = (arg: unknown) => void;

/** A Playwright-shaped fake that replays the events a hostile page would cause. */
function fakeBrowser(options: { gotoFails?: boolean; png?: Buffer; dom?: object } = {}) {
  const handlers = new Map<string, Handler[]>();
  const mainFrame = {};
  const download = { cancel: vi.fn(() => Promise.resolve()) };
  const dialog = { dismiss: vi.fn(() => Promise.resolve()) };
  const emit = (event: string, arg: unknown) => (handlers.get(event) ?? []).forEach((h) => h(arg));
  const page = {
    on: (event: string, handler: Handler) =>
      handlers.set(event, [...(handlers.get(event) ?? []), handler]),
    mainFrame: () => mainFrame,
    goto: vi.fn(async () => {
      await Promise.resolve();
      emit('framenavigated', mainFrame);
      emit('request', { url: () => 'file:///scratch/in/sample.html', method: () => 'GET' });
      emit('request', {
        url: () => 'http://169.254.169.254/latest/meta-data/',
        method: () => 'GET',
      });
      emit('request', { url: () => 'http://mysql:3306/', method: () => 'GET' });
      emit('request', { url: () => 'http://mysql:3306/', method: () => 'GET' });
      emit('request', { url: () => 'https://login.example.test/submit?u=1', method: () => 'POST' });
      emit('request', { url: () => 'data:text/plain,x', method: () => 'GET' });
      emit('download', download);
      emit('dialog', dialog);
      emit('framenavigated', mainFrame);
      emit('framenavigated', {});
      if (options.gotoFails) throw new Error('net::ERR');
    }),
    evaluate: vi.fn(() =>
      Promise.resolve(
        options.dom ?? {
          passwordFields: 1,
          forms: 2,
          actions: ['http://login.example.test/submit', 'file:///x'],
        },
      ),
    ),
    screenshot: vi.fn(() => Promise.resolve(options.png ?? Buffer.from([0x89, 0x50, 0x4e, 0x47]))),
  };
  const context = { newPage: vi.fn(() => Promise.resolve(page)) };
  const browser = {
    version: () => '140.0.7339.16',
    newContext: vi.fn(() => Promise.resolve(context)),
    close: vi.fn(() => Promise.resolve(undefined)),
  };
  return { browser: browser as unknown as Browser, page, context, download, dialog };
}

describe('renderSample', () => {
  it('collects requests, downloads (cancelled), dialogs (dismissed), forms, redirects and a screenshot', async () => {
    const fake = fakeBrowser();
    let launchOptions: LaunchOptions | undefined;
    const sleep = vi.fn((_ms: number) => Promise.resolve(undefined));
    const result = await renderSample(header, Buffer.from('<h1>'), {
      launch: (o) => {
        launchOptions = o;
        return Promise.resolve(fake.browser);
      },
      writeSample: () => 'file:///scratch/in/sample.html',
      sleep,
      now: () => 1_000,
    });
    expect(result.report).toMatchObject({
      v: 1,
      mode: 'browser',
      error: null,
      navigations: 2,
      jsRedirects: 1,
      requests: 6,
      downloadsAttempted: 1,
      dialogs: 1,
      passwordFields: 1,
      forms: 2,
      crossOriginForms: 1,
      screenshot: true,
      chromiumVersion: '140.0.7339.16',
    });
    expect(
      result.report.requestList.map((r) => `${r.method} ${r.scheme}://${r.host}:${r.port}`),
    ).toEqual([
      'GET http://169.254.169.254:80',
      'GET http://mysql:3306',
      'POST https://login.example.test:443',
    ]);
    expect(JSON.stringify(result.report)).not.toContain('meta-data');
    expect(result.screenshot?.length).toBe(4);
    expect(fake.download.cancel).toHaveBeenCalled();
    expect(fake.dialog.dismiss).toHaveBeenCalled();
    expect(fake.browser.close).toHaveBeenCalled();
    // min(wall − 5 s, 15 s), bounded by the remaining budget.
    expect(sleep).toHaveBeenCalledWith(15_000);
    // No proxy, no resolver map, no Chromium sandbox (container controls), scratch-only env.
    expect(launchOptions?.proxy).toBeUndefined();
    expect(launchOptions?.args?.some((a) => a.startsWith('--host-resolver-rules'))).toBe(false);
    expect(launchOptions?.args).toContain('--no-proxy-server');
    expect(launchOptions?.chromiumSandbox).toBe(false);
    expect(launchOptions?.env).toEqual(renderEnvironment());
    expect(fake.context.newPage).toHaveBeenCalled();
    expect((fake.browser.newContext as ReturnType<typeof vi.fn>).mock.calls[0]?.[0]).toMatchObject({
      acceptDownloads: false,
      javaScriptEnabled: true,
      serviceWorkers: 'block',
      viewport: { width: 1280, height: 800 },
    });
  });

  it('a short wall waits wall − 5 s; a screenshot over the cap is dropped; navigation failure is reported', async () => {
    const fake = fakeBrowser({ gotoFails: true, png: Buffer.alloc(2_000_000) });
    const sleep = vi.fn((_ms: number) => Promise.resolve(undefined));
    const result = await renderSample({ ...header, wallTimeoutMs: 12_000 }, Buffer.from('<h1>'), {
      launch: () => Promise.resolve(fake.browser),
      writeSample: () => 'file:///scratch/in/sample.html',
      sleep,
      now: () => 1_000,
    });
    expect(sleep).toHaveBeenCalledWith(7_000);
    expect(result.report.error).toBe('navigation_incomplete');
    expect(result.screenshot).toBeNull();
    expect(result.report.screenshot).toBe(false);
  });

  it('maxArtifacts = 0 takes no screenshot; a launch failure is reported, not thrown', async () => {
    const fake = fakeBrowser();
    const none = await renderSample({ ...header, maxArtifacts: 0 }, Buffer.from('x'), {
      launch: () => Promise.resolve(fake.browser),
      writeSample: () => 'file:///x',
      sleep: () => Promise.resolve(undefined),
    });
    expect(fake.page.screenshot).not.toHaveBeenCalled();
    expect(none.screenshot).toBeNull();
    const failed = await renderSample(header, Buffer.from('x'), {
      launch: () => Promise.reject(new Error('no chromium')),
      writeSample: () => 'file:///x',
    });
    expect(failed.report.error).toBe('launch_failed');
  });
});

describe('helpers', () => {
  it('chromium flags: the worker set without the proxy-only resolver map', () => {
    const args = renderChromiumArgs();
    expect(args).toContain('--disable-quic');
    expect(args).toContain('--disable-background-networking');
    expect(args.join(' ')).not.toContain('host-resolver-rules');
  });

  it('summarizeRequest / isCrossOriginAction', () => {
    expect(summarizeRequest('blob:file:///x', 'GET')).toBeNull();
    expect(summarizeRequest('not a url', 'GET')).toBeNull();
    expect(summarizeRequest('ws://beacon.test:9000/s', 'GET')).toMatchObject({
      scheme: 'ws',
      port: 9000,
    });
    expect(summarizeRequest('http://[fd00:ec2::254]/', 'PATCH')).toMatchObject({
      host: '[fd00:ec2::254]',
      method: 'OTHER',
    });
    expect(isCrossOriginAction('https://x.test/')).toBe(true);
    expect(isCrossOriginAction('file:///scratch/in/sample.html')).toBe(false);
    expect(isCrossOriginAction('')).toBe(false);
  });

  it('writeSampleFile writes the sample read-only under in/', () => {
    const root = mkdtempSync(join(tmpdir(), 'eg-render-'));
    try {
      const url = writeSampleFile(Buffer.from('<svg/>'), 'svg', root);
      expect(url).toBe(`file://${root}/in/sample.svg`);
      expect(readFileSync(join(root, 'in/sample.svg'), 'utf8')).toBe('<svg/>');
      expect(statSync(join(root, 'in/sample.svg')).mode & 0o777).toBe(0o400);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
