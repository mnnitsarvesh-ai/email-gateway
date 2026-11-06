import { urlClickedV1 } from '@email-gateway/event-contracts';
import { continueNonce } from '@email-gateway/url-security';
import { describe, expect, it } from 'vitest';
import {
  buildClickStack,
  completedChain,
  metricValue,
  MESSAGE,
  ORG,
  RECEIVED_AT,
  tokenFor,
  urlRow,
} from './click.test-support';
import { safeDestination, type ClickResponse } from './click.service';

const CLEAN = 'https://clean-site.test/landing?x=1#frag';
const ip = '198.51.100.23';

function setupClean(stack = buildClickStack()) {
  const row = urlRow(CLEAN);
  stack.repository.addUrl(row);
  stack.repository.addScan(row, { verdict: 'clean' });
  return { stack, row, token: tokenFor(stack.config) };
}

const html = (r: ClickResponse): string => (r.kind === 'page' ? r.html : '');

describe('ClickService token outcomes (U12 order)', () => {
  const cases: Array<[string, (t: string) => string, string]> = [
    ['malformed (length)', (t) => t.slice(1), 'malformed'],
    ['malformed (alphabet)', (t) => `${t.slice(0, 61)}!`, 'malformed'],
    ['bad version', (t) => mutateByte(t, 0, 0x02), 'bad_version'],
    ['unknown key id', (t) => mutateByte(t, 1, 0x09), 'unknown_kid'],
    ['bad mac (org byte)', (t) => mutateByte(t, 9, 0x07), 'bad_mac'],
  ];
  for (const [name, mutate, reason] of cases) {
    it(`${name} → 404 invalid, no database access, metric ${reason}`, async () => {
      const { stack, token } = setupClean();
      const response = await stack.service.handle({ token: mutate(token), clientIp: ip });
      expect(response).toMatchObject({ kind: 'page', status: 404, decision: 'invalid' });
      expect(stack.repository.calls).toEqual([]);
      expect(await metricValue(stack.metrics, 'click_token_invalid_total', { reason })).toBe(1);
      expect(
        await metricValue(stack.metrics, 'click_requests_total', { decision: 'invalid' }),
      ).toBe(1);
    });
  }

  it('every tampered byte of a valid token is refused', async () => {
    const { stack, token } = setupClean();
    const raw = Buffer.from(token, 'base64url');
    for (let i = 0; i < raw.length; i += 1) {
      const copy = Buffer.from(raw);
      copy[i] = (copy[i] ?? 0) ^ 0x01;
      const response = await stack.service.handle({
        token: copy.toString('base64url'),
        clientIp: `10.${i}.0.1`,
      });
      expect(response.kind === 'page' && response.status === 404).toBe(true);
    }
    expect(stack.repository.calls).toEqual([]);
  });

  it('a token signed with the previous key is accepted (rotation)', async () => {
    const { stack } = setupClean();
    const response = await stack.service.handle({
      token: tokenFor(stack.config, {}, 'previous'),
      clientIp: ip,
    });
    expect(response).toMatchObject({ kind: 'redirect', decision: 'allowed' });
  });

  it('expired → 410 and an `expired` event without verdict (no URL lookup)', async () => {
    const { stack } = setupClean();
    const token = tokenFor(stack.config, { expiresAt: Math.floor(Date.now() / 1000) - 1 });
    const response = await stack.service.handle({ token, clientIp: ip });
    expect(response).toMatchObject({ kind: 'page', status: 410, decision: 'expired' });
    expect(stack.repository.calls).toEqual(['writeClick']);
    expect(stack.repository.events[0]).toMatchObject({
      decision: 'expired',
      verdict: null,
      reasonCodes: null,
    });
    expect(urlClickedV1.parse(stack.repository.outbox[0]?.payload).verdict).toBeNull();
  });
});

describe('ClickService lookup', () => {
  it('missing row → 404 not_found event', async () => {
    const stack = buildClickStack();
    const response = await stack.service.handle({ token: tokenFor(stack.config), clientIp: ip });
    expect(response).toMatchObject({ kind: 'page', status: 404, decision: 'not_found' });
    expect(stack.repository.events.map((e) => e.decision)).toEqual(['not_found']);
  });

  it('a row of another organization is never found (organization only from the token)', async () => {
    const { stack } = setupClean();
    const response = await stack.service.handle({
      token: tokenFor(stack.config, { organizationId: ORG + 1n }),
      clientIp: ip,
    });
    expect(response).toMatchObject({ status: 404, decision: 'not_found' });
  });

  it('a shifted read is retried once', async () => {
    const { stack, token } = setupClean();
    stack.repository.fail.findUrl = 'inconsistent-once';
    const response = await stack.service.handle({ token, clientIp: ip });
    expect(response).toMatchObject({ kind: 'redirect', decision: 'allowed' });
    expect(stack.repository.calls.filter((c) => c === 'findUrl')).toHaveLength(2);
  });

  it('two shifted reads → 503 (never a redirect)', async () => {
    const { stack, token } = setupClean();
    stack.repository.fail.findUrl = 'inconsistent';
    const response = await stack.service.handle({ token, clientIp: ip });
    expect(response).toMatchObject({ kind: 'page', status: 503, decision: 'unavailable' });
  });

  it('database down → 503 page, no event', async () => {
    const { stack, token } = setupClean();
    stack.repository.fail.findUrl = 'error';
    const response = await stack.service.handle({ token, clientIp: ip });
    expect(response).toMatchObject({ kind: 'page', status: 503, decision: 'unavailable' });
    expect(stack.repository.events).toEqual([]);
  });

  it('settings read failure → 503', async () => {
    const { stack, token } = setupClean();
    stack.repository.fail.tenantUrlSettings = 'error';
    expect(await stack.service.handle({ token, clientIp: ip })).toMatchObject({ status: 503 });
  });
});

describe('ClickService decisions', () => {
  it('clean → 302 to the stored URL only, event + outbox written', async () => {
    const { stack, token } = setupClean();
    const response = await stack.service.handle({ token, clientIp: ip });
    expect(response).toEqual({ kind: 'redirect', location: CLEAN, decision: 'allowed' });
    const event = stack.repository.events[0];
    expect(event).toMatchObject({
      organizationId: ORG,
      messageId: MESSAGE,
      messageReceivedAt: RECEIVED_AT,
      urlSeq: 0,
      decision: 'allowed',
      verdict: 'clean',
      tokenKid: 2,
      clientNetwork: '198.51.100.0/24',
      recheck: { reputation: 'fresh', chain: 'fresh', dynamic: 'none' },
    });
    const outbox = stack.repository.outbox[0];
    expect(outbox).toMatchObject({
      eventType: 'mail.url.clicked.v1',
      aggregateId: MESSAGE.toString(),
    });
    const payload = urlClickedV1.parse(outbox?.payload);
    expect(payload.clickId).toBe(event?.publicId);
    expect(JSON.stringify(payload)).not.toContain('clean-site');
    expect(JSON.stringify(payload)).not.toContain('198.51.100');
  });

  it('no client network stored when CLICK_STORE_CLIENT_NETWORK=false', async () => {
    const { stack, token } = setupClean(
      buildClickStack({ env: { CLICK_STORE_CLIENT_NETWORK: 'false' } }),
    );
    await stack.service.handle({ token, clientIp: ip });
    expect(stack.repository.events[0]?.clientNetwork).toBeNull();
  });

  it('feed hit at click time → 403 block page with the reference id (time-of-click)', async () => {
    const { stack, token } = setupClean();
    stack.repository.addFeed('domain', 'clean-site.test', 'high', 'phishing');
    const response = await stack.service.handle({ token, clientIp: ip });
    expect(response).toMatchObject({ kind: 'page', status: 403, decision: 'blocked' });
    const event = stack.repository.events[0];
    expect(event?.verdict).toBe('malicious');
    expect(event?.reasonCodes).toContain('url.feed_malicious');
    expect(html(response)).toContain(event?.publicId);
  });

  it('allowedDomains never overrides the feed (M1)', async () => {
    const { stack, token } = setupClean();
    stack.repository.settings.set(ORG, { allowedDomains: ['clean-site.test'] });
    stack.repository.addFeed('url', 'https://clean-site.test/landing?x=1', 'critical', 'malware');
    const response = await stack.service.handle({ token, clientIp: ip });
    expect(response).toMatchObject({ status: 403, decision: 'blocked' });
  });

  it('tenant blockedDomains → block (M4)', async () => {
    const { stack, token } = setupClean();
    stack.repository.settings.set(ORG, { blockedDomains: ['clean-site.test'] });
    expect(await stack.service.handle({ token, clientIp: ip })).toMatchObject({
      decision: 'blocked',
    });
  });

  it('suspicious → warn page with a continue nonce; policy block → 403', async () => {
    const row = urlRow('http://10.0.0.5/x'.replace('10.0.0.5', '203.0.113.10'));
    const stack = buildClickStack();
    stack.repository.addUrl(row);
    stack.repository.addScan(row, { verdict: 'suspicious', reasonCodes: ['url.ip_host'] });
    const token = tokenFor(stack.config);
    const warned = await stack.service.handle({ token, clientIp: ip });
    expect(warned).toMatchObject({ kind: 'page', status: 200, decision: 'warned' });
    expect(html(warned)).toContain(`/c/${token}/continue?n=`);
    expect(html(warned)).toContain('203.0.113.10');

    stack.repository.settings.set(ORG, { click: { suspicious: 'block' } });
    expect(await stack.service.handle({ token, clientIp: ip })).toMatchObject({ status: 403 });
  });

  it('allowContinue=false → warn page without a continue link; continue refused', async () => {
    const row = urlRow('http://203.0.113.10/x');
    const stack = buildClickStack();
    stack.repository.addUrl(row);
    stack.repository.addScan(row, { verdict: 'suspicious' });
    stack.repository.settings.set(ORG, { click: { allowContinue: false } });
    const token = tokenFor(stack.config);
    const warned = await stack.service.handle({ token, clientIp: ip });
    expect(html(warned)).not.toContain('/continue');
    const nonce = continueNonce(
      token,
      stack.config.tokenKeys.current,
      Math.floor(Date.now() / 1000),
      600,
    );
    expect(await stack.service.handle({ token, clientIp: ip, nonce })).toMatchObject({
      decision: 'warned',
    });
  });

  it('continue with a valid nonce → 302 `continued`; wrong or old nonce → warn page again', async () => {
    let now = Date.UTC(2026, 10, 6, 12, 0, 0);
    const stack = buildClickStack({ now: () => now });
    const row = urlRow('http://203.0.113.10/x');
    stack.repository.addUrl(row);
    stack.repository.addScan(row, { verdict: 'suspicious' });
    const token = tokenFor(stack.config, { expiresAt: Math.floor(now / 1000) + 86_400 });
    const nonce = continueNonce(token, stack.config.tokenKeys.current, Math.floor(now / 1000), 600);
    expect(await stack.service.handle({ token, clientIp: ip, nonce })).toEqual({
      kind: 'redirect',
      location: 'http://203.0.113.10/x',
      decision: 'continued',
    });
    expect(
      await stack.service.handle({ token, clientIp: ip, nonce: 'A'.repeat(22) }),
    ).toMatchObject({
      decision: 'warned',
    });
    now += 600_000; // next window: still valid (current + previous)
    expect(await stack.service.handle({ token, clientIp: ip, nonce })).toMatchObject({
      decision: 'continued',
    });
    now += 600_000; // two windows later: refused
    expect(await stack.service.handle({ token, clientIp: ip, nonce })).toMatchObject({
      decision: 'warned',
    });
    expect(stack.repository.events.map((e) => e.decision)).toEqual([
      'continued',
      'warned',
      'continued',
      'warned',
    ]);
  });

  it('unknown follows click.unknown (allow / warn / block)', async () => {
    for (const [policy, decision] of [
      ['allow', 'allowed'],
      ['warn', 'warned'],
      ['block', 'blocked'],
    ] as const) {
      const stack = buildClickStack();
      const row = urlRow(CLEAN);
      stack.repository.addUrl(row);
      stack.repository.addScan(row, { verdict: 'clean' });
      stack.repository.fail.feedRows = 'error'; // provider error → unknown
      stack.repository.settings.set(ORG, { click: { unknown: policy } });
      const response = await stack.service.handle({ token: tokenFor(stack.config), clientIp: ip });
      expect(response.decision).toBe(decision);
      expect(stack.repository.events[0]?.verdict).toBe('unknown');
      expect(stack.repository.events[0]?.reasonCodes).toContain('url.reputation_unavailable');
    }
  });

  it('an invalid stored override falls back to the platform settings', async () => {
    const { stack, token } = setupClean();
    stack.repository.settings.set(ORG, { unknownKey: true });
    expect(await stack.service.handle({ token, clientIp: ip })).toMatchObject({
      decision: 'allowed',
    });
  });
});

describe('ClickService recheck', () => {
  it('shortener → chain re-resolved through the fetcher; malicious final → block', async () => {
    const final = 'http://evil-site.test/phish';
    const stack = buildClickStack({
      chain: (url) =>
        Promise.resolve(
          completedChain(url, {
            hops: [
              { host: 'short-link.test', port: null, status: 302, kind: 'initial', blocked: null },
              { host: 'evil-site.test', port: null, status: 200, kind: 'http', blocked: null },
            ],
            finalUrl: final,
          }),
        ),
    });
    const row = urlRow('http://short-link.test/s/evil');
    stack.repository.addUrl(row);
    stack.repository.addScan(row, { verdict: 'clean' });
    stack.repository.addFeed('domain', 'evil-site.test', 'high', 'phishing');
    const response = await stack.service.handle({ token: tokenFor(stack.config), clientIp: ip });
    expect(stack.chainCalls).toEqual(['http://short-link.test/s/evil']);
    expect(response).toMatchObject({ decision: 'blocked' });
    expect(stack.repository.events[0]?.recheck).toMatchObject({ chain: 'fresh' });
  });

  it('the chain is cached for the next click', async () => {
    const stack = buildClickStack();
    const row = urlRow('http://short-link.test/s/clean');
    stack.repository.addUrl(row);
    stack.repository.addScan(row, { verdict: 'clean' });
    const token = tokenFor(stack.config);
    await stack.service.handle({ token, clientIp: ip });
    await new Promise((r) => setTimeout(r, 10));
    await stack.service.handle({ token, clientIp: ip });
    expect(stack.chainCalls).toHaveLength(1);
    expect(stack.repository.events[1]?.recheck).toMatchObject({ chain: 'cached' });
  });

  it('SSRF redirect at click time → redirect_blocked_internal (suspicious → warn)', async () => {
    const stack = buildClickStack({
      chain: () =>
        Promise.resolve({
          status: 'blocked',
          error: null,
          blockedReason: 'metadata',
          hops: [
            { host: 'short-link.test', port: null, status: 302, kind: 'initial', blocked: null },
            {
              host: '169.254.169.254',
              port: null,
              status: null,
              kind: 'http',
              blocked: 'metadata',
            },
          ],
          finalUrl: 'http://169.254.169.254/latest/meta-data/',
          finalStatus: null,
          landing: null,
          durationMs: 3,
        } as const),
    });
    const row = urlRow('http://short-link.test/s/metadata');
    stack.repository.addUrl(row);
    const response = await stack.service.handle({ token: tokenFor(stack.config), clientIp: ip });
    expect(stack.repository.events[0]?.reasonCodes).toContain('url.redirect_blocked_internal');
    expect(response.decision).toBe('warned');
  });

  it('a clean stored, non-shortener URL is re-resolved at click time (brief item 10)', async () => {
    const { stack, token } = setupClean();
    const response = await stack.service.handle({ token, clientIp: ip });
    expect(stack.chainCalls).toEqual(['https://clean-site.test/landing?x=1']);
    expect(response).toMatchObject({ decision: 'allowed' });
  });

  it('a clean scan-time URL whose redirect now leads to a feed-listed host is blocked', async () => {
    const stack = buildClickStack({
      chain: (url) =>
        Promise.resolve(
          completedChain(url, {
            hops: [
              { host: 'clean-site.test', port: null, status: 302, kind: 'initial', blocked: null },
              { host: 'evil-site.test', port: null, status: 200, kind: 'http', blocked: null },
            ],
            finalUrl: 'http://evil-site.test/phish',
          }),
        ),
    });
    const { token } = setupClean(stack);
    stack.repository.addFeed('domain', 'evil-site.test', 'high', 'phishing');
    const response = await stack.service.handle({ token, clientIp: ip });
    expect(response).toMatchObject({ status: 403, decision: 'blocked' });
    expect(stack.repository.events[0]?.reasonCodes).toEqual(
      expect.arrayContaining(['url.feed_malicious', 'url.redirected']),
    );
  });

  it('an intermediate hop host on the feed is looked up and blocks the click', async () => {
    const stack = buildClickStack({
      chain: (url) =>
        Promise.resolve(
          completedChain(url, {
            hops: [
              { host: 'short-link.test', port: null, status: 302, kind: 'initial', blocked: null },
              { host: 'collector-site.test', port: null, status: 302, kind: 'http', blocked: null },
              { host: 'clean-site.test', port: null, status: 200, kind: 'http', blocked: null },
            ],
            finalUrl: 'http://clean-site.test/landing',
          }),
        ),
    });
    const row = urlRow('http://short-link.test/s/hop');
    stack.repository.addUrl(row);
    stack.repository.addScan(row, { verdict: 'clean' });
    stack.repository.addFeed('domain', 'collector-site.test', 'high', 'phishing');
    const response = await stack.service.handle({ token: tokenFor(stack.config), clientIp: ip });
    expect(response).toMatchObject({ decision: 'blocked' });
  });

  it('a shortener re-pointed to a lookalike page with a password form → malicious (M3) → block', async () => {
    const stack = buildClickStack({
      chain: (url) =>
        Promise.resolve(
          completedChain(url, {
            hops: [
              { host: 'short-link.test', port: null, status: 302, kind: 'initial', blocked: null },
              { host: 'examp1ebank.test', port: null, status: 200, kind: 'http', blocked: null },
            ],
            finalUrl: 'https://examp1ebank.test/login',
            landing: {
              passwordFields: 1,
              forms: 1,
              crossOriginFormAction: false,
              formActionHosts: [],
              titleBrandMatches: [],
            },
          }),
        ),
    });
    const row = urlRow('http://short-link.test/s/repointed');
    stack.repository.addUrl(row);
    stack.repository.addScan(row, { verdict: 'clean' });
    const response = await stack.service.handle({ token: tokenFor(stack.config), clientIp: ip });
    expect(stack.repository.calls).toContain('activeDomains');
    expect(stack.repository.events[0]?.verdict).toBe('malicious');
    expect(stack.repository.events[0]?.reasonCodes).toEqual(
      expect.arrayContaining(['url.phishing_high_confidence', 'url.credential_form']),
    );
    expect(response).toMatchObject({ status: 403, decision: 'blocked' });
  });

  it('IP reputation: a host resolving to a feed-listed address is blocked; chain hosts resolved too', async () => {
    const stack = buildClickStack({
      addresses: { 'clean-site.test': ['203.0.113.66'] },
    });
    const { token } = setupClean(stack);
    stack.repository.addFeed('ip', '203.0.113.66', 'high', 'c2');
    const response = await stack.service.handle({ token, clientIp: ip });
    expect(response).toMatchObject({ decision: 'blocked' });
    expect(stack.addressCalls[0]).toEqual(['clean-site.test']);
  });

  it('a truncated URL is never fetched at click time', async () => {
    const stack = buildClickStack();
    const row = urlRow(CLEAN, { truncated: true });
    stack.repository.addUrl(row);
    stack.repository.addScan(row, { verdict: 'clean' });
    await stack.service.handle({ token: tokenFor(stack.config), clientIp: ip });
    expect(stack.chainCalls).toEqual([]);
  });

  it('budget exceeded → unknown (never clean) → policy', async () => {
    const stack = buildClickStack({
      env: { CLICK_RECHECK_BUDGET_MS: '150' },
      chain: (url, signal) =>
        new Promise((resolve) => {
          const timer = setTimeout(() => resolve(completedChain(url)), 5000);
          signal?.addEventListener('abort', () => {
            clearTimeout(timer);
            resolve({ ...completedChain(url), status: 'error', error: 'timeout', landing: null });
          });
        }),
    });
    const row = urlRow('http://short-link.test/s/slow');
    stack.repository.addUrl(row);
    stack.repository.addScan(row, { verdict: 'unknown' });
    const started = Date.now();
    const response = await stack.service.handle({ token: tokenFor(stack.config), clientIp: ip });
    expect(Date.now() - started).toBeLessThan(2000);
    expect(stack.repository.events[0]?.verdict).toBe('unknown');
    expect(response.decision).toBe('warned');
  });

  it('a slow database read past the budget → unknown, response bounded', async () => {
    const stack = buildClickStack({ env: { CLICK_RECHECK_BUDGET_MS: '150' } });
    const row = urlRow(CLEAN);
    stack.repository.addUrl(row);
    stack.repository.addScan(row, { verdict: 'clean' });
    stack.repository.delayMs.latestDynamic = 1000;
    const response = await stack.service.handle({ token: tokenFor(stack.config), clientIp: ip });
    expect(stack.repository.events[0]?.verdict).toBe('unknown');
    expect(response.decision).toBe('warned');
  });

  it('dynamic inspection: password field + brand title → malicious (M5)', async () => {
    const { stack, row, token } = setupClean();
    stack.repository.dynamics.set(`${ORG}:${MESSAGE}:${RECEIVED_AT.getTime()}:0`, {
      scanId: 7n,
      urlSha256: row.urlSha256,
      status: 'completed',
      signals: {
        passwordFields: 1,
        forms: 1,
        crossOriginFormAction: true,
        formActionHosts: ['collector-site.test'],
        downloadAttempted: false,
        blockedRequests: 0,
        requests: 4,
        bytes: 1000,
        titleBrandMatches: ['paypal'],
        jsRedirect: false,
        dialogs: 0,
        navigations: [{ host: 'clean-site.test', status: 200, kind: 'initial' }],
      },
    });
    const response = await stack.service.handle({ token, clientIp: ip });
    expect(response.decision).toBe('blocked');
    expect(stack.repository.events[0]?.reasonCodes).toContain('url.dynamic_phishing');
    expect(stack.repository.events[0]?.recheck).toMatchObject({ dynamic: 'used' });
  });

  it('no stored scan result → lookalike recomputed with the tenant domains', async () => {
    const stack = buildClickStack();
    const row = urlRow('https://examp1ebank.test/login');
    stack.repository.addUrl(row);
    const response = await stack.service.handle({ token: tokenFor(stack.config), clientIp: ip });
    expect(stack.repository.calls).toContain('activeDomains');
    expect(stack.repository.events[0]?.reasonCodes).toContain('url.lookalike_homoglyph');
    expect(response.decision).toBe('warned');
  });
});

describe('ClickService rate limits', () => {
  it('per network / per token / invalid per network → 429; Redis down fails open (counted)', async () => {
    const stack = buildClickStack({
      env: {
        CLICK_RATE_LIMIT_IP_PER_MINUTE: '3',
        CLICK_RATE_LIMIT_TOKEN_PER_MINUTE: '2',
        CLICK_RATE_LIMIT_INVALID_PER_MINUTE: '2',
      },
    });
    const row = urlRow(CLEAN);
    stack.repository.addUrl(row);
    const token = tokenFor(stack.config);
    expect((await stack.service.handle({ token, clientIp: '192.0.2.1' })).decision).toBe('allowed');
    expect((await stack.service.handle({ token, clientIp: '192.0.2.2' })).decision).toBe('allowed');
    expect((await stack.service.handle({ token, clientIp: '192.0.2.3' })).decision).toBe(
      'rate_limited',
    );

    expect((await stack.service.handle({ token: 'x', clientIp: '198.51.100.1' })).decision).toBe(
      'invalid',
    );
    expect((await stack.service.handle({ token: 'y', clientIp: '198.51.100.2' })).decision).toBe(
      'invalid',
    );
    // Same /24: the invalid-token window is full.
    expect((await stack.service.handle({ token: 'z', clientIp: '198.51.100.3' })).decision).toBe(
      'rate_limited',
    );

    stack.redis.down = true;
    const other = tokenFor(stack.config, {
      urlSeq: 0,
      expiresAt: Math.floor(Date.now() / 1000) + 999,
    });
    const response = await stack.service.handle({ token: other, clientIp: '203.0.113.9' });
    expect(response.decision).toBe('allowed');
    expect(await metricValue(stack.metrics, 'click_rate_limiter_errors_total')).toBeGreaterThan(0);
  });
});

describe('ClickService event logging', () => {
  it('a slow event write does not hold the response longer than CLICK_EVENT_WRITE_WAIT_MS', async () => {
    const { stack, token } = setupClean(
      buildClickStack({ env: { CLICK_EVENT_WRITE_WAIT_MS: '50' } }),
    );
    stack.repository.writeDelayMs = 1000;
    const started = Date.now();
    const response = await stack.service.handle({ token, clientIp: ip });
    expect(Date.now() - started).toBeLessThan(800);
    expect(response.decision).toBe('allowed');
    expect(stack.writer.pendingCount).toBe(1);
    expect(await stack.writer.drain(5000)).toBe(true);
    expect(stack.repository.events).toHaveLength(1);
  });

  it('above CLICK_EVENT_MAX_PENDING events are dropped and counted', async () => {
    const { stack, token } = setupClean(
      buildClickStack({ env: { CLICK_EVENT_MAX_PENDING: '1', CLICK_EVENT_WRITE_WAIT_MS: '0' } }),
    );
    stack.repository.writeDelayMs = 300;
    await stack.service.handle({ token, clientIp: ip });
    await stack.service.handle({ token, clientIp: ip });
    expect(await metricValue(stack.metrics, 'click_events_total', { result: 'dropped' })).toBe(1);
    await stack.writer.drain(5000);
    expect(stack.repository.events).toHaveLength(1);
  });

  it('a failed write is counted, the response is unaffected', async () => {
    const { stack, token } = setupClean();
    stack.repository.fail.writeClick = 'error';
    expect((await stack.service.handle({ token, clientIp: ip })).decision).toBe('allowed');
    await stack.writer.drain(1000);
    expect(await metricValue(stack.metrics, 'click_events_total', { result: 'error' })).toBe(1);
  });
});

describe('safeDestination (never an open redirect)', () => {
  it('accepts only http(s) without userinfo, and never a truncated row', () => {
    expect(safeDestination({ url: 'https://a.test/p?q=1#f', truncated: false })).toBe(
      'https://a.test/p?q=1#f',
    );
    expect(safeDestination({ url: 'javascript:alert(1)', truncated: false })).toBeNull();
    expect(safeDestination({ url: 'data:text/html,x', truncated: false })).toBeNull();
    expect(safeDestination({ url: 'https://u:p@a.test/', truncated: false })).toBeNull();
    expect(safeDestination({ url: 'https://a.test/x', truncated: true })).toBeNull();
    expect(safeDestination({ url: 'not a url', truncated: false })).toBeNull();
    expect(safeDestination({ url: 'https://a.test/\r\nSet-Cookie: x', truncated: false })).toBe(
      'https://a.test/Set-Cookie:%20x',
    );
  });
});

function mutateByte(token: string, index: number, value: number): string {
  const raw = Buffer.from(token, 'base64url');
  raw[index] = value;
  return raw.toString('base64url');
}
