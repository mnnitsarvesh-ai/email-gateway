import { createHash } from 'node:crypto';
import { Readable, Writable } from 'node:stream';
import { MetricsService } from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import {
  resolveUrlSettings,
  URL_PLATFORM_DEFAULTS,
  type UrlEffectiveSettings,
} from '@email-gateway/security-contracts';
import {
  type FetchResult,
  LocalFeedProvider,
  loadBrands,
  normalizeUrl,
  type ProviderAnswer,
  type ReputationItem,
  type ReputationProvider,
  ReputationService,
  type RewriteResult,
  verifyToken,
} from '@email-gateway/url-security';
import { describe, expect, it } from 'vitest';
import {
  EmlUnavailableError,
  type EngineDefinite,
  type EngineFailure,
  type EngineScanContext,
} from '../../engine';
import type { PartRead, PartSource } from '../../parts/part-reader';
import type { RewriteStore } from './rewrite-store';
import { UrlMetrics } from './url-metrics';
import { FeedErrorScope, UrlEngine, type UrlEngineLimits } from './url.engine';
import {
  InconsistentUrlReadError,
  type StoredUrlRow,
  type UrlAttachmentRow,
  type UrlParseRow,
  type UrlStore,
} from './url-store';

const ORG = 7n;
const MESSAGE = 55n;
const AT = new Date('2026-11-05T10:00:00.123Z');
const NOW = new Date('2026-11-06T08:00:00.000Z');
const KEY = { id: 3, key: Buffer.alloc(32, 7) };
const sha = (text: string | Buffer): string => createHash('sha256').update(text).digest('hex');
const HTML_KEY = 'org/7/part/2026/11/05/55/0.html';

const LIMITS: UrlEngineLimits = {
  maxUrls: 200,
  maxOccurrences: 5_000,
  maxLength: 2_048,
  maxPartBytes: 10_485_760,
  maxExtraParts: 5,
  extraPartMaxBytes: 2_097_152,
  extractTimeoutMs: 5_000,
  fetchMaxPerMessage: 10,
  suspiciousHops: 4,
  dynamicMaxPerMessage: 3,
  dynamicPendingTtlSeconds: 3_600,
  rewriteMaxMessageBytes: 26_214_400,
  rewriteMaxPartBytes: 5_242_880,
  maxHeadSize: 262_144,
  maxExpiryDays: 90,
};

const htmlOf = (...urls: string[]): string =>
  `<html><body>${urls.map((u) => `<a href="${u}">x</a>`).join(' ')}</body></html>`;
const emlOf = (html: string, headers = ''): Buffer =>
  Buffer.from(
    [
      'From: a@b.test',
      'To: c@d.test',
      'Subject: s',
      ...(headers ? [headers] : []),
      'MIME-Version: 1.0',
      'Content-Type: text/html; charset=utf-8',
      'Content-Transfer-Encoding: 8bit',
      '',
      html,
      '',
    ].join('\r\n'),
  );

class FakeStore implements UrlStore {
  parse: UrlParseRow | null | Error;
  attachments: UrlAttachmentRow[] = [];
  urls: StoredUrlRow[] = [];
  domains: string[] = [];
  feedRows: Array<{ valueSha256: string; severity: string; category: string | null }> = [];
  feedError: Error | null = null;
  readonly feedQuery = (_kind: string, hashes: readonly string[]) => {
    if (this.feedError) return Promise.reject(this.feedError);
    return Promise.resolve(this.feedRows.filter((r) => hashes.includes(r.valueSha256)));
  };

  constructor(html: string | null) {
    this.parse = {
      status: 'parsed',
      limitsExceeded: [],
      attachmentCount: 0,
      textBody: { key: null, sha256: null, sizeBytes: null, charset: null },
      htmlBody:
        html === null
          ? { key: null, sha256: null, sizeBytes: null, charset: null }
          : {
              key: HTML_KEY,
              sha256: sha(html),
              sizeBytes: Buffer.byteLength(html),
              charset: 'utf-8',
            },
      structure: [{ index: 0, contentType: 'text/html', charset: 'utf-8' }],
    };
  }

  loadParse(): Promise<UrlParseRow | null> {
    return this.parse instanceof Error ? Promise.reject(this.parse) : Promise.resolve(this.parse);
  }
  loadAttachments(): Promise<UrlAttachmentRow[]> {
    return Promise.resolve(this.attachments);
  }
  loadMessageUrls(): Promise<StoredUrlRow[]> {
    return Promise.resolve(this.urls);
  }
  activeDomains(): Promise<string[]> {
    return Promise.resolve(this.domains);
  }
}

class FakeParts implements PartSource {
  readonly objects = new Map<string, PartRead>();
  reads: string[] = [];
  read(key: string): Promise<PartRead> {
    this.reads.push(key);
    return Promise.resolve(this.objects.get(key) ?? { kind: 'missing' });
  }
}

/** A DNSBL-like provider answering from a table (or failing as a whole). */
class TableProvider implements ReputationProvider {
  readonly id = 'dnsbl';
  readonly version = 'dnsbl/1;test';
  readonly kinds = ['domain', 'ip'] as const;
  readonly cacheable = false;
  fail = false;
  constructor(readonly listed: Record<string, ProviderAnswer['category']> = {}) {}
  lookup(items: readonly ReputationItem[]): Promise<ProviderAnswer[]> {
    return Promise.resolve(
      items.map((item) => {
        if (this.fail) {
          return {
            ...item,
            status: 'error',
            category: null,
            severity: null,
            detail: 'dns_timeout',
          };
        }
        const category = this.listed[item.value];
        return category
          ? { ...item, status: 'listed', category, severity: 'high', detail: '127.0.1.4' }
          : { ...item, status: 'clear', category: null, severity: null, detail: null };
      }),
    );
  }
}

class FakeFetcher {
  calls: string[] = [];
  results = new Map<string, FetchResult>();
  fetchChain(input: string): Promise<FetchResult> {
    this.calls.push(input);
    const result = this.results.get(input);
    return Promise.resolve(
      result ?? {
        status: 'completed',
        error: null,
        blockedReason: null,
        hops: [
          {
            host: new URL(input).hostname,
            port: null,
            status: 200,
            kind: 'initial',
            blocked: null,
          },
        ],
        finalUrl: input,
        finalStatus: 200,
        landing: null,
        durationMs: 3,
      },
    );
  }
}

/** Host → addresses (the HostAddressResolver contract: public answers only, absent = none). */
class FakeAddresses {
  calls: string[][] = [];
  constructor(readonly table: Record<string, string[]> = {}) {}
  resolve(hosts: Iterable<string>): Promise<Map<string, string[]>> {
    const list = [...hosts];
    this.calls.push(list);
    const out = new Map<string, string[]>();
    for (const host of list) if (this.table[host]) out.set(host, this.table[host]);
    return Promise.resolve(out);
  }
}

class MemoryRewriteStore implements RewriteStore {
  objects = new Map<string, Buffer>();
  fail: Error | null = null;
  async write(
    key: string,
    produce: (sink: Writable) => Promise<RewriteResult>,
  ): Promise<RewriteResult> {
    const chunks: Buffer[] = [];
    const sink = new Writable({
      write(chunk: Buffer, _enc, done) {
        chunks.push(chunk);
        done();
      },
    });
    const result = await produce(sink);
    if (this.fail) throw this.fail;
    if (result.status === 'rewritten') this.objects.set(key, Buffer.concat(chunks));
    return result;
  }
}

function capturedLogger() {
  const lines: string[] = [];
  const destination = new Writable({
    write(chunk: Buffer, _enc, done) {
      lines.push(chunk.toString('utf8'));
      done();
    },
  });
  return {
    logger: createLogger({ service: 'url-engine-test', level: 'debug', destination }),
    lines,
  };
}

interface Setup {
  html?: string | null;
  limits?: Partial<UrlEngineLimits>;
  tokenKey?: typeof KEY | null;
  listed?: Record<string, ProviderAnswer['category']>;
  addresses?: Record<string, string[]>;
}

function setup(options: Setup = {}) {
  const html = options.html === undefined ? htmlOf('http://clean-site.test/a') : options.html;
  const store = new FakeStore(html);
  const parts = new FakeParts();
  if (html !== null) parts.objects.set(HTML_KEY, { kind: 'ok', bytes: Buffer.from(html) });
  const scope = new FeedErrorScope();
  const dnsbl = new TableProvider(options.listed ?? {});
  const registry = new MetricsService({ service: 'url-engine-test' });
  const metrics = UrlMetrics.for(registry);
  const reputation = new ReputationService(
    [new LocalFeedProvider(scope.wrap(store.feedQuery)), dnsbl],
    { timeoutMs: 1_000, breakerThreshold: 5, breakerResetMs: 30_000 },
  );
  const fetcher = new FakeFetcher();
  const addresses = new FakeAddresses(options.addresses ?? {});
  const rewrites = new MemoryRewriteStore();
  const { logger, lines } = capturedLogger();
  const engine = new UrlEngine({
    store,
    parts,
    reputation,
    fetcher,
    addresses,
    cache: null,
    rewriteStore: rewrites,
    feedErrors: scope,
    brands: loadBrands(),
    extraDomains: ['examplebank.test'],
    shorteners: ['short-link.test', 'bit.ly'],
    lookalike: {
      minLabel: 5,
      longLabel: 9,
      maxDistanceShort: 1,
      maxDistanceLong: 2,
      highScore: 0.85,
    },
    limits: { ...LIMITS, ...options.limits },
    tokenKey: options.tokenKey === undefined ? KEY : options.tokenKey,
    clickBaseUrl: 'https://protect.example.com',
    engineVersion: 'url/1;url-fetch/1;abcdef12;12345678',
    probes: { redis: null, dns: () => Promise.resolve('ok'), mode: 'direct' },
    metrics,
    logger,
    now: () => NOW,
  });
  return { engine, store, parts, dnsbl, fetcher, addresses, rewrites, registry, lines, html };
}

function ctx(
  html: string | null,
  override: Record<string, unknown> | null = null,
  extra: Partial<EngineScanContext> = {},
): EngineScanContext {
  const resolved = resolveUrlSettings(URL_PLATFORM_DEFAULTS, override);
  if (!resolved.ok) throw new Error('invalid test settings');
  const eml = emlOf(html ?? '<p>none</p>');
  return {
    organizationId: ORG,
    messageId: MESSAGE,
    receivedAt: AT,
    round: 0,
    direction: 'inbound',
    envelope: {
      clientIp: null,
      clientHelo: null,
      clientName: null,
      envelopeFrom: 'a@b.test',
      recipients: ['c@d.test'],
      queueId: null,
    },
    eml: {
      key: 'org/7/eml/2026/11/05/x.eml',
      sizeBytes: eml.length,
      open: () => Promise.resolve(Readable.from([eml])),
    },
    settings: resolved.settings satisfies UrlEffectiveSettings,
    settingsVersion: 'url-map/1;p=000000000000;t=none',
    ...extra,
  };
}

const definite = (outcome: unknown): EngineDefinite => {
  expect(outcome).toMatchObject({ kind: 'definite' });
  return outcome as EngineDefinite;
};
const failure = (outcome: unknown): EngineFailure => {
  expect(outcome).toMatchObject({ kind: 'failure' });
  return outcome as EngineFailure;
};
const signal = (): AbortSignal => AbortSignal.timeout(30_000);

describe('url engine (step 4.3 U3)', () => {
  it('maps every URL, aggregates, rewrites with verifiable tokens and requests inspections', async () => {
    const html = htmlOf(
      'http://clean-site.test/a',
      'http://examplebank-login.test/verify',
      'http://evil-dbl.test/x',
    );
    const s = setup({ html, listed: { 'evil-dbl.test': 'phishing' } });
    const result = definite(await s.engine.scan(ctx(html), signal()));
    expect(result.result).toMatchObject({
      engine: 'url',
      outcome: 'malicious',
      engineVersion: 'url/1;url-fetch/1;abcdef12;12345678',
      mappingVersion: 'url-map/1',
      score: null,
      requiredScore: null,
      action: null,
    });
    expect(result.result.reasonCodes).toEqual(
      expect.arrayContaining(['url.dnsbl_phishing', 'url.lookalike_combosquat']),
    );
    expect(result.result.reasonCodes).not.toContain('clean.no_findings');
    expect(result.result.signals.find((g) => g.name === 'url:url.dnsbl_phishing')).toEqual({
      name: 'url:url.dnsbl_phishing',
      score: 0,
      options: ['seq 2'],
    });
    const rows = result.childRows!.urls!;
    expect(
      rows.messageUrls.map((u) => [u.urlSeq, u.url, u.firstLifecycleRound, u.extractorVersion]),
    ).toEqual([
      [0, 'http://clean-site.test/a', 0, 'url-extract/1'],
      [1, 'http://examplebank-login.test/verify', 0, 'url-extract/1'],
      [2, 'http://evil-dbl.test/x', 0, 'url-extract/1'],
    ]);
    expect(rows.results.map((r) => [r.urlSeq, r.verdict])).toEqual([
      [0, 'clean'],
      [1, 'suspicious'],
      [2, 'malicious'],
    ]);
    // The lookalike (risk > 0) and the listed URL were fetched; the clean one was not.
    expect(s.fetcher.calls.sort()).toEqual([
      'http://evil-dbl.test/x',
      'http://examplebank-login.test/verify',
    ]);
    expect(rows.results[0]).toMatchObject({ fetchStatus: 'not_attempted', fetchCache: 'none' });
    expect(rows.results[1]!.lookalike![0]).toMatchObject({
      rule: 'L3',
      targetDomain: 'examplebank.test',
    });

    // Rewrite: every eligible link points at the click host; tokens verify with the key.
    expect(rows.rewrite).toMatchObject({
      status: 'rewritten',
      linksRewritten: 3,
      tokenKid: 3,
      expiresAt: new Date(NOW.getTime() + 30 * 86_400_000),
    });
    expect(rows.rewrite.objectKey).toMatch(
      /^org\/7\/rewrite\/2026\/11\/05\/55\/r0-[0-9a-f-]{36}\.eml$/,
    );
    const object = s.rewrites.objects.get(rows.rewrite.objectKey!)!;
    expect(sha(object)).toBe(rows.rewrite.objectSha256);
    const tokens = [
      ...object.toString().matchAll(/https:\/\/protect\.example\.com\/c\/([A-Za-z0-9_-]{62})/g),
    ].map((m) => m[1]!);
    expect(tokens).toHaveLength(3);
    const seqs = tokens.map((t) => {
      const v = verifyToken(t, { current: KEY }, Math.floor(NOW.getTime() / 1000));
      expect(v.outcome).toBe('ok');
      return v.outcome === 'ok' ? v.claims : null;
    });
    expect(seqs.map((c) => c?.urlSeq)).toEqual([0, 1, 2]);
    expect(seqs[0]).toMatchObject({
      organizationId: ORG,
      messageId: MESSAGE,
      receivedAtMs: AT.getTime(),
    });
    expect(rows.results.every((r) => r.rewritten)).toBe(true);

    // Inspections: suspicious/unknown only (the malicious and clean URLs are not inspected).
    expect(rows.inspections).toEqual([
      {
        urlSeq: 1,
        urlSha256: (
          normalizeUrl('http://examplebank-login.test/verify') as {
            ok: true;
            url: { sha256: string };
          }
        ).url.sha256,
        url: 'http://examplebank-login.test/verify',
        requestedAt: NOW,
        deadlineAt: new Date(NOW.getTime() + 3_600_000),
      },
    ]);
    expect(rows.results[1]).toMatchObject({ dynamicRequested: true });
    const metrics = await s.registry.metrics();
    expect(metrics).toMatch(/scan_url_urls_total\{[^}]*verdict="malicious"[^}]*\} 1/);
    expect(metrics).toMatch(/scan_url_extracted_total\{[^}]*source="html_href"[^}]*\} 3/);
    expect(metrics).toMatch(/scan_url_findings_total\{[^}]*code="url.dnsbl_phishing"[^}]*\} 1/);
    expect(metrics).toMatch(/scan_url_rewritten_links_total\{[^}]*part="html"[^}]*\} 3/);
    expect(metrics).toMatch(/scan_url_dynamic_inspections_total\{[^}]*status="requested"[^}]*\} 1/);
    // Never a URL in the logs (hash prefixes only).
    expect(s.lines.join('')).not.toMatch(/clean-site|examplebank|evil-dbl/);
  });

  it('keeps the seqs of earlier rounds on a rescan and writes only new message_urls', async () => {
    const html = htmlOf('http://clean-site.test/a', 'http://clean-site.test/b');
    const s = setup({ html });
    const shaB = (normalizeUrl('http://clean-site.test/b') as { ok: true; url: { sha256: string } })
      .url.sha256;
    s.store.urls = [{ urlSeq: 5, urlSha256: shaB }];
    const rows = definite(await s.engine.scan(ctx(html, null, { round: 1 }), signal())).childRows!
      .urls!;
    expect(rows.messageUrls.map((u) => [u.urlSeq, u.url, u.firstLifecycleRound])).toEqual([
      [6, 'http://clean-site.test/a', 1],
    ]);
    expect(rows.results.map((r) => r.urlSeq)).toEqual([6, 5]);
    expect(rows.rewrite.objectKey).toMatch(/\/r1-/);
  });

  it('U0: no URLs → skipped url.none with a skipped rewrite row, no EML read', async () => {
    const html = '<p>no links</p>';
    const s = setup({ html });
    let opened = false;
    const c = ctx(html);
    c.eml.open = () => {
      opened = true;
      return Promise.resolve(Readable.from([Buffer.alloc(0)]));
    };
    const result = definite(await s.engine.scan(c, signal()));
    expect(result.result).toMatchObject({
      outcome: 'skipped',
      reasonCodes: ['url.none'],
      signals: [],
    });
    expect(result.childRows!.urls).toMatchObject({
      messageUrls: [],
      results: [],
      inspections: [],
      rewrite: { status: 'skipped', skipReason: 'no_urls', objectKey: null },
    });
    expect(opened).toBe(false);
  });

  it('E1: a body not stored (body_size) → suspicious url.content_incomplete; dangerous schemes raise too', async () => {
    const s = setup({ html: null });
    (s.store.parse as UrlParseRow).limitsExceeded = ['body_size'];
    const result = definite(await s.engine.scan(ctx(null), signal()));
    expect(result.result).toMatchObject({
      outcome: 'suspicious',
      reasonCodes: ['url.content_incomplete'],
    });
    expect(result.childRows!.urls!.rewrite).toMatchObject({ skipReason: 'parse_incomplete' });

    const html = '<a href="javascript:alert(1)">x</a>';
    const t = setup({ html });
    const script = definite(await t.engine.scan(ctx(html), signal()));
    expect(script.result).toMatchObject({
      outcome: 'suspicious',
      reasonCodes: ['url.script_scheme'],
    });

    // A body above URL_MAX_PART_BYTES is not scanned: incomplete as well.
    const big = setup({ html: htmlOf('http://clean-site.test/a'), limits: { maxPartBytes: 10 } });
    const bigResult = definite(await big.engine.scan(ctx(big.html), signal()));
    expect(bigResult.result.reasonCodes).toContain('url.content_incomplete');
    expect(big.parts.reads).toEqual([]);
  });

  it('extracts html/text attachment parts (charset from structure), never rewriting them', async () => {
    const s = setup({ html: null });
    const parse = s.store.parse as UrlParseRow;
    parse.attachmentCount = 1;
    parse.structure = [
      { index: 0, contentType: 'multipart/mixed', charset: null },
      { index: 1, contentType: 'text/html', charset: 'iso-8859-1' },
    ];
    const bytes = Buffer.from('<a href="http://clean-site.test/café">x</a>', 'latin1');
    const key = 'org/7/part/2026/11/05/55/1.att';
    s.store.attachments = [
      {
        partIndex: 1,
        filename: 'invoice.html',
        declaredContentType: 'text/html',
        detectedContentType: 'text/html',
        sizeBytes: bytes.length,
        sha256: sha(bytes),
        objectKey: key,
      },
    ];
    s.parts.objects.set(key, { kind: 'ok', bytes });
    const rows = definite(await s.engine.scan(ctx(null), signal())).childRows!.urls!;
    expect(rows.messageUrls).toHaveLength(1);
    expect(rows.messageUrls[0]).toMatchObject({
      url: 'http://clean-site.test/caf%C3%A9',
      sources: { attachment: 1 },
    });
    expect(rows.messageUrls[0]!.flags).toContain('url.in_attachment');
    expect(rows.rewrite).toMatchObject({ status: 'skipped', skipReason: 'no_urls' });
  });

  it('an external provider outage is a definite unknown (never clean, never a failure)', async () => {
    const s = setup();
    s.dnsbl.fail = true;
    const result = definite(await s.engine.scan(ctx(s.html), signal()));
    expect(result.result.outcome).toBe('unknown');
    expect(result.childRows!.urls!.results[0]).toMatchObject({ verdict: 'unknown' });
    expect(result.childRows!.urls!.results[0]!.reasonCodes).toContain('url.reputation_unavailable');
    const answers = result.childRows!.urls!.results[0]!.reputation;
    expect(answers.some((a) => a.provider === 'dnsbl' && a.status === 'error')).toBe(true);
  });

  it('IP reputation of resolved addresses: a domain on a listed IP is flagged (brief item 4)', async () => {
    const html = htmlOf('http://bad-ip-host.test/x', 'http://clean-site.test/a');
    const s = setup({
      html,
      listed: { '203.0.113.66': 'spam' },
      addresses: { 'bad-ip-host.test': ['203.0.113.66'], 'clean-site.test': ['203.0.113.10'] },
    });
    const rows = definite(await s.engine.scan(ctx(html), signal())).childRows!.urls!;
    const bySeq = (url: string) =>
      rows.results.find((r) => r.urlSeq === rows.messageUrls.find((u) => u.url === url)!.urlSeq)!;
    const bad = bySeq('http://bad-ip-host.test/x');
    expect(bad.verdict).toBe('suspicious');
    expect(bad.reasonCodes).toContain('url.dnsbl_spam');
    expect(bad.reputation).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: 'ip', provider: 'dnsbl', status: 'listed' }),
      ]),
    );
    expect(bySeq('http://clean-site.test/a').verdict).toBe('clean');
    expect(s.addresses.calls[0]).toEqual(['bad-ip-host.test', 'clean-site.test']);
  });

  it('chain hops and the final host are resolved too; their listed address flags the URL', async () => {
    const html = htmlOf('http://short-link.test/s/1');
    const s = setup({
      html,
      listed: { '198.51.100.7': 'malware' },
      addresses: { 'final.test': ['198.51.100.7'] },
    });
    s.fetcher.results.set('http://short-link.test/s/1', {
      status: 'completed',
      error: null,
      blockedReason: null,
      hops: [
        { host: 'short-link.test', port: null, status: 302, kind: 'initial', blocked: null },
        { host: 'final.test', port: null, status: 200, kind: 'http', blocked: null },
      ],
      finalUrl: 'http://final.test/landing',
      finalStatus: 200,
      landing: null,
      durationMs: 3,
    });
    const rows = definite(await s.engine.scan(ctx(html), signal())).childRows!.urls!;
    expect(rows.results[0]!.verdict).toBe('malicious');
    expect(rows.results[0]!.reasonCodes).toContain('url.dnsbl_malware');
    expect(s.addresses.calls).toEqual([['short-link.test'], ['final.test']]);
  });

  it('an unresolved shortener (over the fetch limit) is unknown with fetch_not_performed', async () => {
    const html = htmlOf('https://bit.ly/abc');
    const s = setup({ html, limits: { fetchMaxPerMessage: 0 } });
    const rows = definite(await s.engine.scan(ctx(html), signal())).childRows!.urls!;
    expect(rows.results[0]).toMatchObject({ verdict: 'unknown', fetchStatus: 'not_attempted' });
    expect(rows.results[0]!.reasonCodes).toEqual(
      expect.arrayContaining([
        'url.fetch_not_performed',
        'url.fetch_skipped_limit',
        'url.shortened',
      ]),
    );
    expect(s.fetcher.calls).toEqual([]);
  });

  it('applies the tenant lists: blocked → malicious, allowed never rewritten', async () => {
    const html = htmlOf('http://clean-site.test/a', 'http://partner.test/b');
    const s = setup({ html });
    const rows = definite(
      await s.engine.scan(
        ctx(html, { blockedDomains: ['clean-site.test'], allowedDomains: ['partner.test'] }),
        signal(),
      ),
    ).childRows!.urls!;
    expect(rows.results[0]).toMatchObject({ verdict: 'malicious' });
    expect(rows.results[0]!.reasonCodes).toContain('url.tenant_blocked');
    expect(rows.results[1]!.reasonCodes).toContain('url.allowlisted');
    expect(rows.results[1]).toMatchObject({ rewritten: false });
    expect(rows.rewrite).toMatchObject({ linksRewritten: 1 });
  });

  it('skips the rewrite when disabled (tenant) or without a token key, without reading the EML', async () => {
    const s = setup();
    const c = ctx(s.html, { rewrite: { enabled: false } });
    c.eml.open = () => Promise.reject(new Error('must not be read'));
    expect(definite(await s.engine.scan(c, signal())).childRows!.urls!.rewrite).toMatchObject({
      status: 'skipped',
      skipReason: 'disabled',
    });
    const noKey = setup({ tokenKey: null });
    expect(
      definite(await noKey.engine.scan(ctx(noKey.html), signal())).childRows!.urls!.rewrite,
    ).toMatchObject({
      skipReason: 'disabled',
    });
    const outbound = setup();
    expect(
      definite(
        await outbound.engine.scan(ctx(outbound.html, null, { direction: 'outbound' }), signal()),
      ).childRows!.urls!.rewrite,
    ).toMatchObject({ skipReason: 'direction' });
  });

  it('dynamic inspections: at most N, suspicious first, never a URL the content guard refuses, off when disabled', async () => {
    const longToken = 'A'.repeat(600);
    const html = htmlOf(
      'http://new.example-unknown.test/a',
      `http://examplebank-login.test/${longToken}`,
      'http://examplebank-pay.test/x',
      'http://examplebank-help.test/y',
    );
    const s = setup({ html, limits: { dynamicMaxPerMessage: 2 } });
    s.dnsbl.listed['new.example-unknown.test'] = null;
    const rows = definite(await s.engine.scan(ctx(html), signal())).childRows!.urls!;
    expect(rows.inspections.map((i) => i.urlSeq)).toEqual([2, 3]);
    const off = setup({ html });
    expect(
      definite(await off.engine.scan(ctx(html, { dynamicInspection: false }), signal())).childRows!
        .urls!.inspections,
    ).toEqual([]);
  });
});

describe('url engine failures (U3 failure classes, U10)', () => {
  it('a missing parse row is final (parse_row_missing, not retryable, not the engine fault)', async () => {
    const s = setup();
    s.store.parse = null;
    expect(failure(await s.engine.scan(ctx(s.html), signal()))).toMatchObject({
      outcome: 'error',
      errorCode: 'parse_row_missing',
      retryable: false,
      engineFault: false,
    });
  });

  it('an inconsistent writer read is the retryable attempt failure inconsistent_read', async () => {
    const s = setup();
    s.store.parse = new InconsistentUrlReadError('parse', 'identity echo');
    expect(failure(await s.engine.scan(ctx(s.html), signal()))).toMatchObject({
      errorCode: 'inconsistent_read',
      retryable: true,
      engineFault: false,
    });
    expect(await s.registry.metrics()).toMatch(
      /scan_url_inconsistent_reads_total\{[^}]*read="parse"[^}]*\} 1/,
    );
    // An attachment row count that differs from the parse row is a wrong read too.
    const t = setup();
    (t.store.parse as UrlParseRow).attachmentCount = 2;
    expect(failure(await t.engine.scan(ctx(t.html), signal())).errorCode).toBe('inconsistent_read');
    // A local-feed read of another request (thrown by the store) as well.
    const u = setup();
    u.store.feedError = new InconsistentUrlReadError('feed', 'indicator echo');
    expect(failure(await u.engine.scan(ctx(u.html), signal())).errorCode).toBe('inconsistent_read');
  });

  it('part objects: key outside the organization, missing, wrong hash → final, not retryable', async () => {
    const outside = setup();
    (outside.store.parse as UrlParseRow).htmlBody.key = 'org/8/part/2026/11/05/55/0.html';
    expect(failure(await outside.engine.scan(ctx(outside.html), signal()))).toMatchObject({
      errorCode: 'part_key_mismatch',
      retryable: false,
    });
    const missing = setup();
    missing.parts.objects.clear();
    expect(failure(await missing.engine.scan(ctx(missing.html), signal()))).toMatchObject({
      errorCode: 'part_unavailable',
      retryable: false,
    });
    const corrupt = setup();
    corrupt.parts.objects.set(HTML_KEY, { kind: 'integrity' });
    expect(failure(await corrupt.engine.scan(ctx(corrupt.html), signal()))).toMatchObject({
      errorCode: 'part_integrity',
      retryable: false,
    });
  });

  it('infrastructure errors are thrown (transient): the feed database and the rewrite upload', async () => {
    const feed = setup();
    const outage = Object.assign(new Error('db down'), {
      name: 'PrismaClientKnownRequestError',
      code: 'P1001',
    });
    feed.store.feedError = outage;
    await expect(feed.engine.scan(ctx(feed.html), signal())).rejects.toBe(outage);
    const upload = setup();
    const s3 = new Error('S3 unavailable');
    upload.rewrites.fail = s3;
    await expect(upload.engine.scan(ctx(upload.html), signal())).rejects.toBe(s3);
  });

  it('a missing EML (rewrite) is final eml_unavailable', async () => {
    const s = setup();
    const c = ctx(s.html);
    c.eml.open = () => Promise.reject(new EmlUnavailableError());
    expect(failure(await s.engine.scan(c, signal()))).toMatchObject({
      errorCode: 'eml_unavailable',
      retryable: false,
    });
  });

  it('an extraction over its budget is the retryable extract_timeout; an aborted call is timeout', async () => {
    const s = setup({ limits: { extractTimeoutMs: -1 } });
    expect(failure(await s.engine.scan(ctx(s.html), signal()))).toMatchObject({
      outcome: 'timeout',
      errorCode: 'extract_timeout',
      retryable: true,
      engineFault: false,
    });
    const t = setup();
    const aborted = new AbortController();
    aborted.abort();
    expect(failure(await t.engine.scan(ctx(t.html), aborted.signal))).toMatchObject({
      outcome: 'timeout',
      errorCode: 'timeout',
      retryable: true,
    });
  });
});

describe('url engine readiness (U3)', () => {
  it('reports the cache, the DNS resolver and the egress mode', async () => {
    const { engine } = setup();
    const [check] = engine.healthChecks();
    expect(check!.name).toBe('url-engine');
    await expect(check!.check()).resolves.toEqual({
      cache: 'disabled',
      dns: 'ok',
      egress: 'direct',
    });
  });
});
