import { createHash } from 'node:crypto';
import { uuidv7 } from '@email-gateway/common';
import {
  chainCacheKey,
  FETCHER_VERSION,
  normalizeUrl,
  parseTokenKey,
  RestrictedResolver,
  UrlCache,
  verifyToken,
} from '@email-gateway/url-security';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { requireEnv } from './support/fixtures';
import { ScanFixtures } from './support/scan';
import {
  emlWithBodies,
  linksHtml,
  requireUrlTest,
  testCaFile,
  UrlFixtures,
  UrlPipeline,
} from './support/urls';

/**
 * Rewriting end to end (U11, U12), the authenticated cache (U6), provider outages (U3, U17),
 * rescans with stable seqs (U3 step 3) and idempotency (U16, §2.0 invariant 4) against the real
 * stack. See url-scan.test.ts for the infrastructure.
 */

const fx = new ScanFixtures();
const ufx = new UrlFixtures(fx);
let ca: ReturnType<typeof testCaFile>;
let pipeline: UrlPipeline;
const sha256 = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');

/** Counts the resolver's DNS queries (cache hits must not query). */
class CountingResolver extends RestrictedResolver {
  /** DNSBL queries (resolve4Raw). */
  queries = 0;
  /** Host resolutions (resolveAll: the fetcher's per-hop resolution and the IP-reputation lookup of host addresses). */
  resolutions: string[] = [];
  override resolve4Raw(name: string, signal?: AbortSignal): Promise<string[]> {
    this.queries += 1;
    return super.resolve4Raw(name, signal);
  }
  override resolveAll(host: string, signal?: AbortSignal): Promise<{ v4: string[]; v6: string[] }> {
    this.resolutions.push(host);
    return super.resolveAll(host, signal);
  }
}

beforeAll(async () => {
  ca = testCaFile();
  await requireUrlTest();
  pipeline = UrlPipeline.start(fx, ca.path);
});

afterAll(async () => {
  await pipeline?.close();
  await ufx.cleanup();
  await fx.cleanup();
  ca?.cleanup();
});

const clickBase = (): string => pipeline.config.URL_CLICK_BASE_URL.replace(/\/+$/, '');
const tokensIn = (text: string): string[] =>
  [
    ...text.matchAll(
      new RegExp(
        `${clickBase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/c/([A-Za-z0-9_-]{62})`,
        'g',
      ),
    ),
  ].map((m) => m[1]!);

describe('rewriting end to end (U11, U12)', () => {
  it('writes a tagged rewritten copy, signs verifiable tokens, keeps excluded links and the original', async () => {
    const org = await fx.organization('rewrite');
    await ufx.settings(org, { rewrite: { excludedDomains: ['www.clean-site.test'] } });
    const short = `http://short-link.test/s/clean?run=${fx.suffix}-rw`;
    ufx.track(short);
    const eml = emlWithBodies(
      'Read http://clean-site.test/landing and http://www.clean-site.test/keep now.',
      linksHtml('http://clean-site.test/landing', short, 'http://www.clean-site.test/keep') +
        '<a href="mailto:help@clean-site.test">mail</a>',
    );
    const message = await ufx.message(org, eml);
    expect(await pipeline.deliver(fx.parsed(message))).toBe('handled');
    const state = await ufx.state(message);
    const rewrite = state.rewrites[0]!;
    expect(rewrite).toMatchObject({
      status: 'rewritten',
      skipReason: null,
      linksRewritten: 3,
      partsRewritten: 2,
      tokenKid: Number(process.env.URL_TOKEN_KEY_CURRENT_ID ?? '1'),
    });
    expect(rewrite.objectKey).toMatch(
      new RegExp(
        `^org/${org.toString()}/rewrite/\\d{4}/\\d{2}/\\d{2}/${message.messageId.toString()}/r0-[0-9a-f-]{36}\\.eml$`,
      ),
    );
    const expiry = rewrite.expiresAt!.getTime() - Date.now();
    expect(expiry).toBeGreaterThan(29 * 86_400_000);
    expect(expiry).toBeLessThanOrEqual(30 * 86_400_000);

    const object = await ufx.object(rewrite.objectKey!);
    expect(object.tags).toEqual({ 'eg-object': 'rewrite' });
    expect(object.type).toBe('message/rfc822');
    expect(sha256(object.body)).toBe(rewrite.objectSha256);
    expect(object.body.length).toBe(rewrite.objectSizeBytes);
    const text = object.body.toString('utf8');
    // Excluded and mailto links are untouched; the eligible ones are gone.
    expect(text).toContain('http://www.clean-site.test/keep');
    expect(text).toContain('mailto:help@clean-site.test');
    expect(text).not.toContain('href="http://clean-site.test/landing"');
    expect(text).not.toContain(short);

    const keys = {
      current: parseTokenKey(
        requireEnv('URL_TOKEN_KEY_CURRENT'),
        Number(process.env.URL_TOKEN_KEY_CURRENT_ID ?? '1'),
      ),
    };
    const tokens = tokensIn(text);
    expect(tokens).toHaveLength(3);
    const seqs = new Set<number>();
    for (const token of tokens) {
      const verified = verifyToken(token, keys);
      expect(verified.outcome).toBe('ok');
      if (verified.outcome !== 'ok') continue;
      expect(verified.claims).toMatchObject({
        organizationId: org,
        messageId: message.messageId,
        receivedAtMs: message.receivedAt.getTime(),
      });
      seqs.add(verified.claims.urlSeq);
    }
    const seqOf = (url: string) => state.messageUrls.find((u) => u.url === url)!.urlSeq;
    expect([...seqs].sort()).toEqual(
      [seqOf('http://clean-site.test/landing'), seqOf(short)].sort(),
    );
    expect(
      state.results.find((r) => r.urlSeq === seqOf('http://www.clean-site.test/keep')),
    ).toMatchObject({
      rewritten: false,
    });
    expect(state.results.find((r) => r.urlSeq === seqOf(short))).toMatchObject({ rewritten: true });

    // The original EML is never modified.
    const original = await fx.prisma.emailMessage.findFirstOrThrow({
      where: { id: message.messageId, receivedAt: message.receivedAt },
      select: { emlObjectKey: true, emlSha256: true },
    });
    expect(sha256((await ufx.object(original.emlObjectKey)).body)).toBe(original.emlSha256);
    expect(await pipeline.text()).toMatch(
      /scan_url_rewrites_total\{[^}]*result="rewritten"[^}]*\} 1/,
    );
  });

  it('skips a signed message as a whole (signed_smime) and leaves no object', async () => {
    const org = await fx.organization('signed');
    const eml = [
      'From: alice@clean.scan.test',
      'To: bob@customer.scan.test',
      'Subject: signed',
      'MIME-Version: 1.0',
      'Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256; boundary="s"',
      '',
      '--s',
      'Content-Type: text/plain; charset=utf-8',
      '',
      'Pay here: http://clean-site.test/landing',
      '--s',
      'Content-Type: application/pkcs7-signature; name="smime.p7s"',
      'Content-Transfer-Encoding: base64',
      'Content-Disposition: attachment; filename="smime.p7s"',
      '',
      Buffer.from('not a real signature').toString('base64'),
      '--s--',
      '',
    ].join('\r\n');
    const message = await ufx.message(org, eml);
    expect(await pipeline.deliver(fx.parsed(message))).toBe('handled');
    const state = await ufx.state(message);
    expect(state.rewrites[0]).toMatchObject({ status: 'skipped', skipReason: 'signed_smime' });
    expect(state.results[0]).toMatchObject({ rewritten: false });
    expect(await ufx.rewriteObjects(org)).toEqual([]);
  });

  it('honours dkimSignedPolicy=skip for a DKIM-signed message (dkim_policy)', async () => {
    const org = await fx.organization('dkim');
    await ufx.settings(org, { rewrite: { dkimSignedPolicy: 'skip' } });
    const message = await ufx.message(
      org,
      emlWithBodies(
        'http://clean-site.test/landing',
        linksHtml('http://clean-site.test/landing'),
        'DKIM-Signature: v=1; a=rsa-sha256; d=clean.scan.test; s=sel; h=from; bh=x; b=y',
      ),
    );
    expect(await pipeline.deliver(fx.parsed(message))).toBe('handled');
    const state = await ufx.state(message);
    expect(state.rewrites[0]).toMatchObject({
      status: 'skipped',
      skipReason: 'dkim_policy',
      dkimSigned: true,
    });
    expect(await ufx.rewriteObjects(org)).toEqual([]);
  });
});

describe('rescans and idempotency (U3, U16)', () => {
  it('a rescan keeps the seqs, writes new results and a new rewrite object', async () => {
    const org = await fx.organization('rescan');
    const message = await ufx.message(
      org,
      emlWithBodies(
        'http://clean-site.test/one http://clean-site.test/two',
        linksHtml('http://clean-site.test/two', 'http://clean-site.test/three'),
      ),
    );
    expect(await pipeline.deliver(fx.parsed(message))).toBe('handled');
    const first = await ufx.state(message);
    expect(first.messageUrls.map((u) => [u.urlSeq, u.url])).toEqual([
      [0, 'http://clean-site.test/one'],
      [1, 'http://clean-site.test/two'],
      [2, 'http://clean-site.test/three'],
    ]);
    expect(await pipeline.deliver(await fx.rescan(message))).toBe('handled');
    const second = await ufx.state(message);
    expect(second.messageUrls.map((u) => [u.urlSeq, u.url, u.firstLifecycleRound])).toEqual(
      first.messageUrls.map((u) => [u.urlSeq, u.url, 0]),
    );
    expect(second.scans).toHaveLength(2);
    expect(second.results).toHaveLength(6);
    for (const scan of second.scans) {
      expect(second.results.filter((r) => r.scanId === scan.id).map((r) => r.urlSeq)).toEqual([
        0, 1, 2,
      ]);
    }
    expect(second.rewrites.map((r) => r.lifecycleRound)).toEqual([0, 1]);
    expect(second.rewrites[1]!.objectKey).toMatch(/\/r1-/);
    expect(second.rewrites[0]!.objectKey).not.toBe(second.rewrites[1]!.objectKey);
  });

  it('the same event three times and two event ids of one round write one final and one set of child rows', async () => {
    const org = await fx.organization('idempotent');
    const message = await ufx.message(
      org,
      emlWithBodies('http://new-domain.test/offer', linksHtml('http://clean-site.test/landing')),
    );
    const event = fx.parsed(message);
    const outcomes = [];
    for (let i = 0; i < 3; i += 1) outcomes.push(await pipeline.deliver(event));
    expect(outcomes).toEqual(['handled', 'duplicate', 'duplicate']);
    // Another event id of the same round: the engine's final exists, nothing is written.
    await pipeline.deliver(fx.parsed(message, uuidv7()));
    const state = await ufx.state(message);
    expect(state.finals).toHaveLength(1);
    expect(state.finals[0]).toMatchObject({ outcome: 'suspicious' });
    expect(state.messageUrls).toHaveLength(2);
    expect(state.results).toHaveLength(2);
    expect(state.rewrites).toHaveLength(1);
    // new-domain.test is suspicious: one inspection and one outbox row.
    expect(state.inspections).toHaveLength(1);
    expect(state.inspectionEvents).toHaveLength(1);
    const payload = state.inspectionEvents[0]!.payload as Record<string, unknown>;
    expect(payload).toMatchObject({
      inspectionId: state.inspections[0]!.id.toString(),
      url: 'http://new-domain.test/offer',
      urlSeq: state.inspections[0]!.urlSeq,
      lifecycleRound: 0,
    });
    expect(
      Date.parse(payload.deadlineAt as string) - Date.parse(payload.requestedAt as string),
    ).toBe(pipeline.config.URL_DYNAMIC_PENDING_TTL_SECONDS * 1000);
    expect(state.inspections[0]).toMatchObject({ status: 'pending' });
    expect(state.inspectionEvents[0]!.eventId).toBe(state.inspections[0]!.requestedEventId);
    // Each attempt writes its own object; the finalized row names one of them (orphans expire).
    expect(await ufx.rewriteObjects(org)).toContain(state.rewrites[0]!.objectKey);
    expect(state.results.find((r) => r.urlSeq === state.inspections[0]!.urlSeq)).toMatchObject({
      dynamicRequested: true,
    });
  });
});

describe('the authenticated cache (U6)', () => {
  it('a second scan answers from the cache without DNSBL queries or fetches', async () => {
    const resolver = new CountingResolver({
      servers: pipeline.config.URL_DNS_SERVERS,
      timeoutMs: 1500,
      tries: 1,
    });
    const cached = UrlPipeline.start(fx, ca.path, { engine: { resolver } });
    try {
      const short = `http://short-link.test/s/clean?run=${fx.suffix}-cache`;
      ufx.track(short);
      const org = await fx.organization('cache');
      const message = await ufx.message(org, emlWithBodies('', linksHtml(short)));
      expect(await cached.deliver(fx.parsed(message))).toBe('handled');
      const first = await ufx.state(message);
      expect(first.results[0]).toMatchObject({ fetchCache: 'miss', fetchStatus: 'completed' });
      // DNSBL answers may already be in the shared cache from an earlier run; the first scan
      // resolved at least the chain's hops.
      const queries = resolver.queries;
      const resolutions = resolver.resolutions.length;
      expect(resolutions).toBeGreaterThan(0);

      expect(await cached.deliver(await fx.rescan(message))).toBe('handled');
      const second = await ufx.state(message);
      const row = second.results.find((r) => r.scanId === second.scans[1]!.id)!;
      expect(row).toMatchObject({ fetchCache: 'hit', fetchStatus: 'completed', verdict: 'clean' });
      const answers = row.reputation as Array<Record<string, unknown>>;
      expect(
        answers.filter((a) => a.provider !== 'local_feed').every((a) => a.cache === 'hit'),
      ).toBe(true);
      expect(resolver.queries).toBe(queries);
      // Host addresses (IP reputation) are resolved again on every scan — DNS answers are not
      // cached by the gateway (the recursive resolver honours their TTL) — but the chain is not
      // fetched again: exactly the URL host and the cached chain's final host, once each.
      expect(resolver.resolutions.slice(resolutions)).toEqual([
        'short-link.test',
        'clean-site.test',
      ]);
    } finally {
      await cached.close();
    }
  });

  it('rejects a forged chain entry (wrong MAC), fetches again and overwrites it', async () => {
    const short = `http://short-link.test/s/clean?run=${fx.suffix}-forged`;
    ufx.track(short);
    const identity = (normalizeUrl(short) as { ok: true; url: { identity: string } }).url.identity;
    const key = chainCacheKey(FETCHER_VERSION, identity);
    const forged = JSON.stringify({
      status: 'completed',
      error: null,
      blockedReason: null,
      hops: [{ host: 'short-link.test', port: null, status: 200, kind: 'initial', blocked: null }],
      finalUrl: 'http://clean-site.test/landing',
      finalStatus: 200,
      landing: null,
      durationMs: 1,
    });
    await ufx.redis.client.set(key, `${'0'.repeat(64)}.${forged}`, 'EX', 300);
    const org = await fx.organization('forged');
    const message = await ufx.message(org, emlWithBodies('', linksHtml(short)));
    expect(await pipeline.deliver(fx.parsed(message))).toBe('handled');
    const state = await ufx.state(message);
    expect(state.results[0]).toMatchObject({ fetchCache: 'miss', fetchStatus: 'completed' });
    expect(await pipeline.text()).toMatch(
      /url_cache_total\{[^}]*cache="chain"[^}]*result="rejected"[^}]*\} [1-9]/,
    );
    const cache = new UrlCache({
      client: ufx.redis.client,
      hmacKey: requireEnv('URL_CACHE_HMAC_KEY'),
    });
    expect((await cache.getChain(FETCHER_VERSION, identity)).result).toBe('hit');
  });
});

describe('provider outage (U3, U6, U17)', () => {
  it('an unreachable resolver makes URLs unknown (never clean) and opens the provider breaker', async () => {
    const outage = UrlPipeline.start(fx, ca.path, {
      overrides: {
        URL_DNS_SERVERS: '127.0.0.1:9',
        URL_CACHE_ENABLED: 'false',
        URL_PROVIDER_BREAKER_THRESHOLD: '1',
        URL_PROVIDER_TIMEOUT_MS: '2000',
      },
    });
    try {
      const org = await fx.organization('outage');
      const message = await ufx.message(
        org,
        emlWithBodies('', linksHtml(`http://clean-site.test/outage-${fx.suffix}`)),
      );
      expect(await outage.deliver(fx.parsed(message))).toBe('handled');
      const state = await ufx.state(message);
      expect(state.results[0]!.verdict).toBe('unknown');
      expect(state.results[0]!.reasonCodes as string[]).toContain('url.reputation_unavailable');
      expect(state.finals[0]).toMatchObject({ outcome: 'unknown' });
      const answers = state.results[0]!.reputation as Array<Record<string, unknown>>;
      expect(answers.some((a) => a.provider === 'dnsbl' && a.status === 'error')).toBe(true);
      const metrics = await outage.text();
      expect(metrics).toMatch(/url_provider_breaker_state\{[^}]*provider="dnsbl"[^}]*\} 2/);
      expect(metrics).toMatch(
        /url_reputation_lookups_total\{[^}]*provider="dnsbl"[^}]*result="error"[^}]*\} [1-9]/,
      );

      // With the breaker open the next message is answered `error` at once: still unknown.
      const next = await ufx.message(
        org,
        emlWithBodies('', linksHtml(`http://clean-site.test/outage-2-${fx.suffix}`)),
      );
      expect(await outage.deliver(fx.parsed(next))).toBe('handled');
      expect((await ufx.state(next)).results[0]!.verdict).toBe('unknown');
    } finally {
      await outage.close();
    }
  });
});
