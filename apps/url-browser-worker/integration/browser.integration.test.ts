import { execFile } from 'node:child_process';
import { resolve } from 'node:path';
import { promisify } from 'node:util';
import { encodeEvent, uuidv7 } from '@email-gateway/common';
import {
  EventTypes,
  urlInspectionCompletedV1,
  urlInspectionRequestedV1,
  type UrlInspectionCompletedV1,
} from '@email-gateway/event-contracts';
import { normalizeUrl } from '@email-gateway/url-security';
import { connect, type Channel, type ChannelModel, type ConfirmChannel } from 'amqplib';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { FORBIDDEN_KEYS, FORBIDDEN_PREFIXES } from '../src/config';

/**
 * Focused container suite of the isolated browser worker (step 4.3 §9 "url-browser-worker"),
 * run on the host against the live containers:
 *
 *   docker compose --profile url-browser build url-browser-worker      # alone, once
 *   URL_BROWSER_MAX_JOBS_PER_BROWSER=3 URL_BROWSER_JOB_TIMEOUT_MS=10000 \
 *     docker compose --profile smtp-test --profile url-browser up -d url-egress-proxy url-browser-worker
 *   pnpm --filter @email-gateway/url-browser-worker test:integration
 *
 * Requests are published to `email.security` as `org.<test org>.mail.url.inspection_requested.v1`
 * (admin user); results are read from a temporary exclusive queue bound to the result key of the
 * test organization. Never run together with the analytics or observability profiles on the 8 GB
 * VM. No value of .env is printed.
 */

const run = promisify(execFile);
const REPO = resolve(__dirname, '../../..');
const ORG = String(920_000_000 + Math.floor(Math.random() * 1_000_000));
const VHOST = process.env.RABBITMQ_VHOST ?? 'email-gateway';
const JOB_TIMEOUT_EXPECTED_MS = 10_000;

let admin: ChannelModel;
let publishChannel: ConfirmChannel;
let resultChannel: Channel;
const results = new Map<string, UrlInspectionCompletedV1>();
const waiters = new Map<string, (r: UrlInspectionCompletedV1) => void>();
let nextInspection = BigInt(Date.now()) * 1000n;

async function compose(args: string[], timeout = 60_000): Promise<string> {
  const { stdout } = await run('docker', ['compose', ...args], {
    cwd: REPO,
    timeout,
    maxBuffer: 4 << 20,
  });
  return stdout;
}

/** Runs a small Node script inside a container; returns its stdout. */
async function inContainer(service: string, script: string): Promise<string> {
  return compose(['exec', '-T', service, 'node', '-e', script], 90_000);
}

function vhostUrl(url: string): string {
  const parsed = new URL(url);
  if (parsed.pathname === '/' || parsed.pathname === '')
    parsed.pathname = `/${encodeURIComponent(VHOST)}`;
  return parsed.toString();
}

async function inspect(url: string, deadlineMs = 300_000): Promise<UrlInspectionCompletedV1> {
  const normalized = normalizeUrl(url);
  if (!normalized.ok) throw new Error('test URL does not normalize');
  nextInspection += 1n;
  const inspectionId = nextInspection.toString();
  const now = Date.now();
  const payload = urlInspectionRequestedV1.parse({
    inspectionId,
    messageId: '1',
    receivedAt: new Date(now - 60_000).toISOString(),
    scanId: '1',
    lifecycleRound: 0,
    urlSeq: 0,
    url: normalized.url.redirect,
    urlSha256: normalized.url.sha256,
    requestedAt: new Date(now - 1000).toISOString(),
    deadlineAt: new Date(now + deadlineMs).toISOString(),
  });
  const encoded = encodeEvent(
    {
      eventId: uuidv7(),
      eventType: EventTypes.UrlInspectionRequested,
      occurredAt: new Date(now).toISOString(),
      correlationId: `wp4-browser-${inspectionId}`,
      organizationId: ORG,
      payload,
    },
    'wp4-browser-suite',
  );
  const result = new Promise<UrlInspectionCompletedV1>((resolveResult) => {
    const ready = results.get(inspectionId);
    if (ready) resolveResult(ready);
    else waiters.set(inspectionId, resolveResult);
  });
  await new Promise<void>((resolvePublish, reject) => {
    publishChannel.publish(
      encoded.exchange,
      encoded.routingKey,
      encoded.content,
      encoded.options,
      (err: unknown) => (err ? reject(new Error('publish not confirmed')) : resolvePublish()),
    );
  });
  return result;
}

async function metric(
  service: string,
  port: number,
  name: string,
  labels: string,
): Promise<number> {
  const out = await inContainer(
    service,
    `fetch('http://127.0.0.1:${port}/metrics').then(r=>r.text()).then(t=>{const l=t.split('\\n').find(x=>x.startsWith('${name}{')&&x.includes('${labels}'));console.log(l?l.split(' ').pop():'0')})`,
  );
  return Number(out.trim() || '0');
}

beforeAll(async () => {
  const ps = await compose([
    'ps',
    '--format',
    '{{.Service}} {{.Health}}',
    'url-browser-worker',
    'url-egress-proxy',
  ]);
  expect(ps).toMatch(/url-browser-worker healthy/);
  expect(ps).toMatch(/url-egress-proxy healthy/);
  admin = await connect(vhostUrl(process.env.RABBITMQ_URL ?? ''));
  publishChannel = await admin.createConfirmChannel();
  resultChannel = await admin.createChannel();
  const { queue } = await resultChannel.assertQueue('', {
    exclusive: true,
    autoDelete: true,
    durable: false,
  });
  await resultChannel.bindQueue(
    queue,
    'email.security',
    `org.${ORG}.mail.url.inspection_completed.v1`,
  );
  await resultChannel.consume(
    queue,
    (msg) => {
      if (!msg) return;
      const envelope = JSON.parse(msg.content.toString('utf8')) as {
        organizationId: string;
        payload: unknown;
      };
      expect(envelope.organizationId).toBe(ORG);
      const payload = urlInspectionCompletedV1.parse(envelope.payload);
      results.set(payload.inspectionId, payload);
      waiters.get(payload.inspectionId)?.(payload);
    },
    { noAck: true },
  );
}, 60_000);

afterAll(async () => {
  await admin?.close().catch(() => undefined);
});

describe('real Chromium through the egress proxy (url-test)', () => {
  it('password form posting cross-origin', async () => {
    const r = await inspect('http://phish-login.test/');
    expect(r).toMatchObject({
      status: 'completed',
      errorCode: null,
      finalHost: 'phish-login.test',
    });
    expect(r.signals.passwordFields).toBeGreaterThanOrEqual(1);
    expect(r.signals.forms).toBeGreaterThanOrEqual(1);
    expect(r.signals.crossOriginFormAction).toBe(true);
    expect(r.signals.formActionHosts).toContain('collector-site.test');
    expect(r.navigations[0]).toEqual({ host: 'phish-login.test', status: 200, kind: 'initial' });
    expect(r.browserVersion).toMatch(/^chromium-headless-shell\/\d+/);
  });

  it('JavaScript redirect followed and reported', async () => {
    const r = await inspect('http://clean-site.test/js-redirect');
    expect(r.status).toBe('completed');
    expect(r.signals.jsRedirect).toBe(true);
    expect(r.navigations.map((n) => n.kind)).toEqual(['initial', 'js']);
    expect(r.finalHost).toBe('clean-site.test');
  });

  it('download blocked and reported', async () => {
    const r = await inspect('http://clean-site.test/download');
    expect(r.signals.downloadAttempted).toBe(true);
  });

  it('JS requests to 169.254.169.254 and 127.0.0.1 are refused by the proxy', async () => {
    const before = await metric(
      'url-egress-proxy',
      3091,
      'url_egress_blocked_total',
      'reason="metadata"',
    );
    const r = await inspect('http://clean-site.test/js-fetch-internal');
    expect(r.status).toBe('completed');
    expect(r.signals.blockedRequests).toBeGreaterThanOrEqual(2);
    expect(
      await metric('url-egress-proxy', 3091, 'url_egress_blocked_total', 'reason="metadata"'),
    ).toBeGreaterThan(before);
  });

  it('a navigation to an internal address is refused (proxy_refused)', async () => {
    const r = await inspect('http://short-link.test/s/internal');
    expect(r.signals.blockedRequests).toBeGreaterThanOrEqual(1);
    expect(r.navigations.map((n) => n.host)).toEqual(['short-link.test', '127.0.0.1']);
  });

  it('job timeout', async () => {
    const started = Date.now();
    const r = await inspect('http://slow-site.test/');
    expect(r).toMatchObject({ status: 'failed', errorCode: 'job_timeout' });
    expect(r.durationMs).toBeGreaterThanOrEqual(JOB_TIMEOUT_EXPECTED_MS - 100);
    expect(Date.now() - started).toBeLessThan(60_000);
  }, 120_000);

  it('passed deadline → failed/deadline_passed without navigating', async () => {
    const r = await inspect('http://clean-site.test/landing', -1);
    expect(r).toMatchObject({ status: 'failed', errorCode: 'deadline_passed', navigations: [] });
  });

  it('browser restarted after URL_BROWSER_MAX_JOBS_PER_BROWSER jobs', async () => {
    for (let i = 0; i < 3; i += 1) await inspect('http://clean-site.test/landing');
    expect(
      await metric('url-browser-worker', 3090, 'url_browser_restarts_total', 'reason="max_jobs"'),
    ).toBeGreaterThanOrEqual(1);
    expect(
      await metric('url-browser-worker', 3090, 'url_browser_jobs_total', 'result="completed"'),
    ).toBeGreaterThanOrEqual(3);
  }, 180_000);
});

describe('isolation', () => {
  it('direct egress from the worker container fails (internal network, no DNS)', async () => {
    const out = await inContainer(
      'url-browser-worker',
      `const net=require('node:net');const dns=require('node:dns');
       const tcp=(h,p)=>new Promise(r=>{const s=net.connect({host:h,port:p,timeout:3000});s.on('connect',()=>{s.destroy();r('open')});s.on('timeout',()=>{s.destroy();r('blocked')});s.on('error',()=>r('blocked'))});
       Promise.all([tcp('203.0.113.10',80),tcp('1.1.1.1',443),tcp('172.31.250.53',53),
         new Promise(r=>dns.lookup('clean-site.test',e=>r(e?'blocked':'open'))),
         fetch('http://203.0.113.10/landing',{signal:AbortSignal.timeout(4000)}).then(()=>'open',()=>'blocked')])
       .then(v=>console.log(v.join(',')))`,
    );
    expect(out.trim()).toBe('blocked,blocked,blocked,blocked,blocked');
  });

  it('the proxy refuses loopback, metadata and private targets for the worker', async () => {
    const out = await inContainer(
      'url-browser-worker',
      `const http=require('node:http');const auth='Basic '+Buffer.from('eg:'+process.env.URL_EGRESS_PROXY_TOKEN).toString('base64');
       const ask=(t)=>new Promise(r=>{const q=http.request({host:'url-egress-proxy',port:3128,path:t,headers:{'proxy-authorization':auth}},s=>{s.resume();r(s.statusCode+':'+(s.headers['x-egress-blocked-reason']||''))});q.on('error',()=>r('error'));q.end()});
       Promise.all(['http://127.0.0.1/','http://169.254.169.254/latest/meta-data/','http://10.0.0.5/','http://loopback-a.test/','http://clean-site.test/landing'].map(ask)).then(v=>console.log(v.join(',')))`,
    );
    expect(out.trim()).toBe('403:loopback,403:metadata,403:private,403:loopback,200:');
  });

  it('the worker environment holds no database, S3, Redis or token/cache key', async () => {
    const names = (
      await inContainer('url-browser-worker', `console.log(Object.keys(process.env).join('\\n'))`)
    )
      .split('\n')
      .map((n) => n.trim())
      .filter(Boolean);
    const forbidden = names.filter(
      (n) =>
        (FORBIDDEN_KEYS as readonly string[]).includes(n) ||
        FORBIDDEN_PREFIXES.some((p) => n.startsWith(p)),
    );
    expect(forbidden).toEqual([]);
    expect(names).not.toContain('MYSQL_CLICK_PASSWORD');
    expect(names).not.toContain('RABBITMQ_PASSWORD');
  });

  it('readiness reports the Chromium sandbox mode', async () => {
    const out = await inContainer(
      'url-browser-worker',
      `fetch('http://127.0.0.1:3090/health/ready').then(r=>r.json()).then(j=>console.log(JSON.stringify(j.checks.map(c=>[c.name,c.status,c.details&&c.details.chromiumSandbox]))))`,
    );
    const checks = JSON.parse(out) as Array<[string, string, unknown]>;
    expect(checks).toEqual(
      expect.arrayContaining([
        ['rabbitmq', 'ok', null],
        ['browser', 'ok', expect.any(Boolean)],
      ]),
    );
  });

  it('the eg-url-browser user cannot read other queues or publish other keys', async () => {
    const browserUser = await connect(vhostUrl(process.env.RABBITMQ_URL_BROWSER_URL ?? ''));
    const refused = async (op: (ch: ConfirmChannel) => Promise<unknown>): Promise<string> => {
      const ch = await browserUser.createConfirmChannel();
      let closeReason = '';
      ch.on('error', (error: Error) => {
        closeReason = String(error.message);
      });
      try {
        await op(ch);
        await ch.close();
        return 'allowed';
      } catch (error) {
        // The broker's 403 arrives as the channel's error event ("channel closed" on the op).
        await new Promise((r) => setTimeout(r, 100));
        const text = `${String((error as Error).message)} ${closeReason}`;
        return /ACCESS_REFUSED|ACCESS-REFUSED|\b403\b/.test(text) ? 'refused' : 'error';
      }
    };
    const publish = (key: string) => (ch: ConfirmChannel) =>
      new Promise<void>((ok, fail) => {
        ch.publish('email.security', key, Buffer.from('{}'), {}, (err: unknown) =>
          err ? fail(new Error('channel closed')) : ok(),
        );
        ch.once('close', () => fail(new Error('channel closed')));
      });
    expect(await refused((ch) => ch.consume('scan.spam', () => undefined))).toBe('refused');
    expect(await refused((ch) => ch.consume('scan.url.results', () => undefined))).toBe('refused');
    expect(await refused((ch) => ch.consume('scan.url', () => undefined))).toBe('refused');
    expect(await refused(publish(`org.${ORG}.mail.url.clicked.v1`))).toBe('refused');
    expect(await refused(publish(`org.${ORG}.mail.url.inspection_requested.v1`))).toBe('refused');
    expect(await refused(publish(`org.${ORG}.mail.message.scanned.v1`))).toBe('refused');
    await browserUser.close().catch(() => undefined);
  });
});
