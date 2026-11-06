import { domainToASCII } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ScanFixtures, type ScanMessage } from './support/scan';
import {
  emlWithBodies,
  emlWithHtml,
  linksHtml,
  requireUrlTest,
  testCaFile,
  UrlFixtures,
  UrlPipeline,
  type UrlState,
  urlTestHttp,
} from './support/urls';

/**
 * The url engine against the real stack (step 4.3 §9 "Package integration"): MySQL writer,
 * MinIO, Redis, dns-sink (127.0.0.1:${DNS_SINK_HOST_PORT}) and url-test (URL_FETCH_TEST_DIAL_MAP).
 * Messages are parsed by the real MIME stage; the engine is called through the round service.
 * Fetched URLs carry `?run=<suffix>` so the shared chain cache of earlier runs never answers.
 */

const fx = new ScanFixtures();
const ufx = new UrlFixtures(fx);
let ca: ReturnType<typeof testCaFile>;
/** Platform default fetch mode (`suspicious`). */
let pipeline: UrlPipeline;
/** URL_SCAN_TIME_FETCH=all, 50 fetches per message (chains, SSRF corpus, bounded responses). */
let fetchAll: UrlPipeline;
const run = (): string => `run=${fx.suffix}`;

beforeAll(async () => {
  ca = testCaFile();
  await requireUrlTest();
  pipeline = UrlPipeline.start(fx, ca.path);
  fetchAll = UrlPipeline.start(fx, ca.path, {
    overrides: { URL_SCAN_TIME_FETCH: 'all', URL_FETCH_MAX_PER_MESSAGE: '50' },
  });
});

afterAll(async () => {
  await pipeline?.close();
  await fetchAll?.close();
  await ufx.cleanup();
  await fx.cleanup();
  ca?.cleanup();
});

async function scan(
  p: UrlPipeline,
  label: string,
  urls: string[],
  options: { text?: string } = {},
): Promise<{ message: ScanMessage; state: UrlState }> {
  ufx.track(...urls);
  const org = await fx.organization(label);
  const message = await ufx.message(
    org,
    options.text !== undefined
      ? emlWithBodies(options.text, linksHtml(...urls))
      : emlWithHtml(linksHtml(...urls)),
  );
  expect(await p.deliver(fx.parsed(message))).toBe('handled');
  return { message, state: await ufx.state(message) };
}

/** The result row of a URL (by its stored redirect form). */
function resultOf(state: UrlState, url: string) {
  const row = state.messageUrls.find((u) => u.url === url);
  if (!row) throw new Error(`URL not stored: ${url}`);
  const result = state.results.find((r) => r.urlSeq === row.urlSeq);
  if (!result) throw new Error(`no result for seq ${String(row.urlSeq)}`);
  return { ...result, reasonCodes: result.reasonCodes as string[] };
}

describe('redirect chains and short URLs (U8, U9)', () => {
  it('follows 2 and 4 redirects, caps 10 and loops', async () => {
    const two = `http://redirect-chain.test/hop/1/clean?${run()}`;
    const four = `http://redirect-chain.test/hop/3/clean?${run()}`;
    const ten = `http://short-link.test/s/chain10?${run()}`;
    const loop = `http://short-link.test/s/loop?${run()}`;
    const { state } = await scan(fetchAll, 'chains', [two, four, ten, loop]);
    expect(resultOf(state, two)).toMatchObject({
      verdict: 'clean',
      fetchStatus: 'completed',
      hopCount: 2,
      finalUrl: 'http://clean-site.test/landing',
      finalStatus: 200,
    });
    expect(resultOf(state, two).reasonCodes).toContain('url.redirected');
    expect(resultOf(state, four)).toMatchObject({ verdict: 'suspicious', hopCount: 4 });
    expect(resultOf(state, four).reasonCodes).toContain('url.many_redirects');
    for (const url of [ten, loop]) {
      expect(resultOf(state, url)).toMatchObject({
        verdict: 'suspicious',
        fetchStatus: 'error',
        fetchError: 'redirect_limit',
      });
      expect(resultOf(state, url).reasonCodes).toContain('url.redirect_limit');
    }
    // The chain JSON holds hosts only (no path, no query).
    const chain = resultOf(state, two).redirectChain as Array<Record<string, unknown>>;
    expect(chain.map((h) => h.host)).toEqual([
      'redirect-chain.test',
      'redirect-chain.test',
      'clean-site.test',
    ]);
    expect(JSON.stringify(chain)).not.toContain('/hop/');
    expect(state.finals[0]).toMatchObject({ outcome: 'suspicious' });
  });

  it('resolves shorteners: clean final, feed-listed final, internal and metadata targets', async () => {
    const clean = `http://short-link.test/s/clean?${run()}`;
    const evil = `http://short-link.test/s/evil?${run()}-evil`;
    const internal = `http://short-link.test/s/internal?${run()}`;
    const metadata = `http://short-link.test/s/metadata?${run()}`;
    const id = await ufx.indicator('domain', 'evil-site.test', 'high', 'phishing');
    try {
      const { state } = await scan(pipeline, 'shorteners', [clean, evil, internal, metadata]);
      expect(resultOf(state, clean)).toMatchObject({ verdict: 'clean', fetchStatus: 'completed' });
      expect(resultOf(state, clean).reasonCodes).toEqual(
        expect.arrayContaining(['url.shortened', 'url.redirected', 'clean.no_findings']),
      );
      expect(resultOf(state, evil)).toMatchObject({
        verdict: 'malicious',
        finalHost: 'evil-site.test',
      });
      expect(resultOf(state, evil).reasonCodes).toContain('url.feed_malicious');
      for (const url of [internal, metadata]) {
        expect(resultOf(state, url)).toMatchObject({
          verdict: 'suspicious',
          fetchStatus: 'blocked',
        });
        expect(resultOf(state, url).reasonCodes).toContain('url.redirect_blocked_internal');
      }
      expect(state.finals[0]).toMatchObject({ outcome: 'malicious' });
    } finally {
      await ufx.removeIndicator(id);
    }
  });
});

describe('reputation: local feed, DNSBL, RDAP (U6)', () => {
  it('local feed url, domain (via a subdomain) and IP hits are malicious; a removal applies at once', async () => {
    const byUrl = 'http://clean-site.test/feed-listed-page';
    const bySubdomain = 'http://login.evil-site.test/account';
    // An IP no corpus name resolves to (resolved addresses are looked up too, so listing the
    // url-test server's 203.0.113.10 would flag every corpus URL of concurrent suites).
    const byIp = 'http://203.0.113.99/landing';
    const ids = [
      await ufx.indicator('url', byUrl, 'critical', 'phishing'),
      await ufx.indicator('domain', 'evil-site.test', 'high', 'malware'),
      await ufx.indicator('ip', '203.0.113.99', 'high', 'c2'),
    ];
    const { message, state } = await scan(pipeline, 'feed', [byUrl, bySubdomain, byIp]);
    for (const url of [byUrl, bySubdomain, byIp]) {
      expect(resultOf(state, url).verdict).toBe('malicious');
      expect(resultOf(state, url).reasonCodes).toContain('url.feed_malicious');
    }
    const feedAnswer = (resultOf(state, byUrl).reputation as Array<Record<string, unknown>>).find(
      (a) => a.provider === 'local_feed' && a.status === 'listed',
    );
    // Authoritative: never cached.
    expect(feedAnswer).toMatchObject({ kind: 'url', cache: 'none', severity: 'critical' });

    for (const id of ids) await ufx.removeIndicator(id);
    const rescan = await fx.rescan(message);
    expect(await pipeline.deliver(rescan)).toBe('handled');
    const after = await ufx.state(message);
    const scanId = after.scans[1]!.id;
    const second = after.results.filter((r) => r.scanId === scanId);
    for (const url of [byUrl, bySubdomain]) {
      const seq = after.messageUrls.find((u) => u.url === url)!.urlSeq;
      const row = second.find((r) => r.urlSeq === seq)!;
      expect(row.reasonCodes as string[]).not.toContain('url.feed_malicious');
      expect(row.verdict).not.toBe('malicious');
    }
  });

  it('the test DBL lists phishing and malware domains (malicious); RDAP flags a new domain', async () => {
    const phishing = 'http://evil-dbl.test/login';
    const malware = 'http://malware-dbl.test/payload';
    const fresh = 'http://new-domain.test/welcome';
    const { state } = await scan(pipeline, 'dnsbl', [phishing, malware, fresh]);
    expect(resultOf(state, phishing)).toMatchObject({ verdict: 'malicious' });
    expect(resultOf(state, phishing).reasonCodes).toContain('url.dnsbl_phishing');
    expect(resultOf(state, malware).reasonCodes).toContain('url.dnsbl_malware');
    expect(resultOf(state, fresh)).toMatchObject({ verdict: 'suspicious' });
    expect(resultOf(state, fresh).reasonCodes).toContain('url.new_domain');
  });

  it('IP reputation of resolved addresses: bad-ip-host.test resolves to an RBL-listed IP', async () => {
    const badIp = `http://bad-ip-host.test/x?${run()}`;
    const clean = `http://clean-site.test/landing?${run()}`;
    const { state } = await scan(pipeline, 'resolved-ip', [badIp, clean]);
    expect(resultOf(state, badIp).verdict).toBe('suspicious');
    expect(resultOf(state, badIp).reasonCodes).toContain('url.dnsbl_spam');
    expect(resultOf(state, badIp).reputation as Array<Record<string, unknown>>).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ provider: 'dnsbl', kind: 'ip', status: 'listed' }),
      ]),
    );
    // The url-test server's own address is looked up and clear.
    expect(resultOf(state, clean).verdict).toBe('clean');
    expect(resultOf(state, clean).reputation as Array<Record<string, unknown>>).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ provider: 'dnsbl', kind: 'ip', status: 'clear' }),
      ]),
    );
  });
});

describe('lookalikes and Unicode (U7, U10 M3)', () => {
  it('flags the Cyrillic homoglyph, the high-confidence phishing page, a combosquat and mixed script', async () => {
    const homoglyph = `http://${domainToASCII('exаmplebank.test')}/?${run()}`;
    const phish = `http://examp1ebank.test/login?${run()}`;
    const combo = `http://examplebank-login.test/?${run()}`;
    const mixed = `http://${domainToASCII('secureаccount-portal.test')}/`;
    const { state } = await scan(pipeline, 'lookalike', [homoglyph, phish, combo, mixed]);
    expect(resultOf(state, homoglyph).reasonCodes).toEqual(
      expect.arrayContaining(['url.lookalike_homoglyph', 'url.idn']),
    );
    expect(resultOf(state, homoglyph).verdict).not.toBe('clean');
    // examp1ebank.test (L2/L1 on the skeleton) serves a password form: M3 malicious.
    expect(resultOf(state, phish)).toMatchObject({ verdict: 'malicious' });
    expect(resultOf(state, phish).reasonCodes).toEqual(
      expect.arrayContaining(['url.phishing_high_confidence', 'url.credential_form']),
    );
    expect(resultOf(state, combo).reasonCodes).toContain('url.lookalike_combosquat');
    expect(resultOf(state, mixed).reasonCodes).toContain('url.mixed_script');
    const stored = state.messageUrls.find((u) => u.url === homoglyph)!;
    expect(stored).toMatchObject({ unicodeHost: 'exаmplebank.test', hostKind: 'domain' });
  });
});

describe('SSRF (U8): direct links, redirects, internal names, rebinding, ports', () => {
  it('blocks direct links to internal addresses in every encoding', async () => {
    const urls = [
      'http://127.0.0.1/',
      'http://2130706433/',
      'http://0x7f.0.0.1/',
      'http://[::1]/',
      'http://[::ffff:127.0.0.1]/',
      'http://169.254.169.254/latest/meta-data/',
      'http://10.0.0.5/',
      'http://100.64.0.1/',
    ].map((u) => `${u}?${run()}`);
    const { state } = await scan(pipeline, 'ssrf-direct', urls);
    for (const row of state.results) {
      expect(row.fetchStatus).toBe('blocked');
      expect(row.verdict).toBe('suspicious');
      expect(row.reasonCodes as string[]).toEqual(
        expect.arrayContaining(['url.ip_host', 'url.redirect_blocked_internal']),
      );
    }
    // 127.0.0.1, 2130706433 and 0x7f.0.0.1 normalize to one URL (U5).
    expect(state.results).toHaveLength(6);
    expect(await pipeline.text()).toMatch(
      /url_fetch_blocked_total\{[^}]*reason="loopback"[^}]*component="engine"[^}]*\} [1-9]/,
    );
  });

  it('blocks every redirect into an internal target and names resolving internally', async () => {
    const cases = [
      'loopback',
      'loopback-short',
      'decimal',
      'octal',
      'hex',
      'v6-loopback',
      'v6-mapped-hex',
      'v6-mapped',
      'zero',
      'private-10',
      'private-172',
      'private-192',
      'cgnat',
      'metadata',
      'metadata-v6',
      'metadata-name',
      'localhost',
      'file',
      'gopher',
    ];
    const redirects = cases.map((c) => `http://clean-site.test/to/${c}?${run()}`);
    const names = [
      'private-a.test',
      'loopback-a.test',
      'meta-a.test',
      'cgnat-a.test',
      'zero-a.test',
      'v6-loop.test',
      'mapped-v6.test',
      'ula-v6.test',
      'mixed-a.test',
    ].map((n) => `http://${n}/?${run()}`);
    const { state } = await scan(fetchAll, 'ssrf-redirects', [...redirects, ...names]);
    for (const url of [...redirects, ...names]) {
      const row = resultOf(state, url);
      expect(row.fetchStatus, url).toBe('blocked');
      expect(row.verdict, url).toBe('suspicious');
      expect(row.reasonCodes, url).toContain('url.redirect_blocked_internal');
    }
    // The first hop was requested; the blocked hop never was (no path in the chain JSON).
    const first = resultOf(state, redirects[0]!).redirectChain as Array<Record<string, unknown>>;
    expect(first[0]).toMatchObject({ host: 'clean-site.test', status: 302, blocked: null });
    expect(first.at(-1)).toMatchObject({ blocked: 'loopback' });
  });

  it('DNS rebinding: private first is blocked; public first uses the validated address; a redirect back re-resolves and is blocked', async () => {
    const reset = async (first: 'public' | 'private') => {
      const res = await fetch(`${urlTestHttp()}/reset?first=${first}`);
      expect(res.ok).toBe(true);
    };
    // The engine resolves every URL host once for IP reputation before the fetch (one A query
    // of the alternating responder), so the fetcher's own resolution gets the SECOND answer of
    // the sequence: `public` first → the fetcher sees the private answer, and vice versa.
    await reset('public');
    const a = await scan(fetchAll, 'rebind-private', [`http://rebind.test/landing?${run()}-a`]);
    expect(a.state.results[0]).toMatchObject({ fetchStatus: 'blocked', verdict: 'suspicious' });
    await reset('private');
    const b = await scan(fetchAll, 'rebind-public', [`http://rebind.test/landing?${run()}-b`]);
    expect(b.state.results[0]).toMatchObject({ fetchStatus: 'completed', finalStatus: 200 });
    await reset('private');
    const c = await scan(fetchAll, 'rebind-again', [`http://rebind.test/rebind-again?${run()}-c`]);
    expect(c.state.results[0]).toMatchObject({ fetchStatus: 'blocked', verdict: 'suspicious' });
    expect(c.state.results[0]!.reasonCodes as string[]).toContain('url.redirect_blocked_internal');
  });

  it('refuses a non-standard port (unknown, never clean)', async () => {
    const url = `http://clean-site.test:8080/?${run()}`;
    const { state } = await scan(fetchAll, 'port', [url]);
    expect(resultOf(state, url)).toMatchObject({ verdict: 'unknown', fetchStatus: 'blocked' });
    expect(resultOf(state, url).reasonCodes).toEqual(
      expect.arrayContaining(['url.fetch_blocked_port', 'url.nonstandard_port']),
    );
  });
});

describe('bounded responses (U8)', () => {
  it('slow, trickling, huge, many-header and gzip-bomb pages end bounded and never clean', async () => {
    const urls = [
      'http://slow-site.test/',
      'http://trickle-site.test/',
      'http://huge-site.test/',
      'http://many-headers.test/',
      'http://gzip-bomb.test/',
    ].map((u) => `${u}?${run()}`);
    const started = Date.now();
    const { state } = await scan(fetchAll, 'bounded', urls);
    expect(Date.now() - started).toBeLessThan(30_000);
    const byHost = (host: string) =>
      state.results.find(
        (r) => state.messageUrls.find((u) => u.urlSeq === r.urlSeq)?.host === host,
      )!;
    expect(byHost('slow-site.test')).toMatchObject({ fetchStatus: 'error', fetchError: 'timeout' });
    expect(byHost('trickle-site.test')).toMatchObject({
      fetchStatus: 'error',
      fetchError: 'timeout',
    });
    expect(byHost('many-headers.test').fetchStatus).toBe('error');
    expect(byHost('gzip-bomb.test')).toMatchObject({
      fetchStatus: 'error',
      fetchError: 'too_large',
    });
    // A huge page is read up to URL_FETCH_MAX_BODY_BYTES, then the socket is destroyed.
    expect(['completed', 'error']).toContain(byHost('huge-site.test').fetchStatus);
    for (const host of [
      'slow-site.test',
      'trickle-site.test',
      'many-headers.test',
      'gzip-bomb.test',
    ]) {
      expect(byHost(host).verdict).toBe('unknown');
    }
  });
});

describe('content rules (U0, E1) and extra parts (U4)', () => {
  it('no URLs → skipped (url.none) with a skipped rewrite row', async () => {
    const org = await fx.organization('no-urls');
    const message = await ufx.message(org, emlWithBodies('no links here', '<p>none</p>'));
    expect(await pipeline.deliver(fx.parsed(message))).toBe('handled');
    const state = await ufx.state(message);
    expect(state.finals).toHaveLength(1);
    expect(state.finals[0]).toMatchObject({ outcome: 'skipped', reasonCodes: ['url.none'] });
    expect(state.messageUrls).toHaveLength(0);
    expect(state.rewrites[0]).toMatchObject({ status: 'skipped', skipReason: 'no_urls' });
    expect(state.scans[0]).toMatchObject({ status: 'completed' });
  });

  it('a body that was not stored → url.content_incomplete (at least suspicious), never skipped', async () => {
    const org = await fx.organization('incomplete');
    const message = await ufx.message(org, emlWithBodies('x'.repeat(200), '<p>small</p>'), {
      mime: { MIME_MAX_BODY_BYTES: '100' },
    });
    const parse = await fx.prisma.emailMessageParse.findFirstOrThrow({
      where: { messageId: message.messageId, receivedAt: message.receivedAt },
    });
    expect(parse.limitsExceeded).toContain('body_size');
    expect(await pipeline.deliver(fx.parsed(message))).toBe('handled');
    const state = await ufx.state(message);
    expect(state.finals[0]).toMatchObject({ outcome: 'suspicious' });
    expect(state.finals[0]!.reasonCodes as string[]).toContain('url.content_incomplete');
    expect(state.rewrites[0]).toMatchObject({ status: 'skipped', skipReason: 'parse_incomplete' });
  });

  it('extracts URLs of an HTML attachment (url.in_attachment, never rewritten)', async () => {
    const org = await fx.organization('attachment');
    const eml = [
      'From: alice@clean.scan.test',
      'To: bob@customer.scan.test',
      'Subject: attachment links',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="m"',
      '',
      '--m',
      'Content-Type: text/plain; charset=utf-8',
      '',
      'see attachment',
      '--m',
      'Content-Type: text/html; charset=iso-8859-1; name="invoice.html"',
      'Content-Disposition: attachment; filename="invoice.html"',
      'Content-Transfer-Encoding: base64',
      '',
      Buffer.from('<a href="http://clean-site.test/from-attachment">pay</a>', 'latin1').toString(
        'base64',
      ),
      '--m--',
      '',
    ].join('\r\n');
    const message = await ufx.message(org, eml);
    expect(await pipeline.deliver(fx.parsed(message))).toBe('handled');
    const state = await ufx.state(message);
    expect(state.messageUrls).toHaveLength(1);
    expect(state.messageUrls[0]).toMatchObject({
      url: 'http://clean-site.test/from-attachment',
      sources: { attachment: 1 },
    });
    expect(state.messageUrls[0]!.flags as string[]).toContain('url.in_attachment');
    expect(state.results[0]).toMatchObject({ rewritten: false });
    expect(state.rewrites[0]).toMatchObject({ status: 'skipped', skipReason: 'no_urls' });
  });

  it('a missing body object is a final part_unavailable failure (never a verdict)', async () => {
    const org = await fx.organization('part-missing');
    const message = await ufx.message(org, emlWithBodies('http://clean-site.test/a', '<p>b</p>'));
    const parse = await fx.prisma.emailMessageParse.findFirstOrThrow({
      where: { messageId: message.messageId, receivedAt: message.receivedAt },
    });
    await ufx.deleteObject(parse.textBodyObjectKey!);
    expect(await pipeline.deliver(fx.parsed(message))).toBe('handled');
    const state = await ufx.state(message);
    expect(state.finals[0]).toMatchObject({ outcome: 'error', errorCode: 'part_unavailable' });
    expect(state.finals[0]!.reasonCodes).toEqual(['engine.part_unavailable']);
    expect(state.results).toHaveLength(0);
    expect(state.scans[0]).toMatchObject({ status: 'failed' });
  });
});
