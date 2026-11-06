import { BadRequestException } from '@nestjs/common';
import { Prisma } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import type {
  AttachmentResultRow,
  AuthResultRow,
  EngineResultRow,
  MessageUrlRow,
  ScanRoundRow,
  UrlInspectionRow,
  UrlResultRow,
} from '../repositories/message-scans-read.repository';
import {
  attachmentOf,
  attachmentsOf,
  decodeScanCursor,
  encodeScanCursor,
  engineOf,
  rewriteOf,
  roundOf,
  stringArray,
  symbolsOf,
  type UrlInputs,
  urlsOf,
} from './message-scans';

const at = (s: number) => new Date(Date.UTC(2026, 10, 5, 8, 0, s));

const scan = (id: bigint, round: number, overrides: Partial<ScanRoundRow> = {}): ScanRoundRow => ({
  id,
  lifecycleRound: round,
  scanKind: round === 0 ? 'initial' : 'rescan',
  status: 'running',
  scanVerdict: null,
  reasonCodes: null,
  requiredEngines: ['rspamd'],
  startedAt: at(0),
  completedAt: null,
  deadlineAt: at(59),
  ...overrides,
});

const row = (overrides: Partial<EngineResultRow>): EngineResultRow => ({
  scanId: 1n,
  engine: 'rspamd',
  engineVersion: '3.12.1',
  outcome: 'error',
  score: null,
  requiredScore: null,
  action: null,
  reasonCodes: ['engine.error'],
  errorCode: 'unavailable',
  settingsVersion: null,
  durationMs: 10,
  evidence: null,
  attempt: 1,
  isFinal: false,
  completedAt: at(1),
  ...overrides,
});

describe('message scans mapping (step 4.1 S16)', () => {
  it('parses stored JSON defensively', () => {
    expect(stringArray(['a.b', 'c.d'])).toEqual(['a.b', 'c.d']);
    expect(stringArray(null)).toEqual([]);
    expect(stringArray([1, 'x'])).toEqual([]);
    expect(symbolsOf(null)).toEqual([]);
    expect(symbolsOf({ signals: 'x' })).toEqual([]);
    expect(
      symbolsOf({
        signals: [
          { name: 'R_SPF_FAIL', score: 1, options: ['-all'] },
          { name: '', score: 1 },
          { name: 'NO_OPTIONS', score: -0.5 },
          { name: 'BAD', score: 'x' },
        ],
      }),
    ).toEqual([
      { name: 'R_SPF_FAIL', score: 1, options: ['-all'] },
      { name: 'NO_OPTIONS', score: -0.5, options: [] },
    ]);
    const many = { signals: Array.from({ length: 250 }, (_, i) => ({ name: `S${i}`, score: 0 })) };
    expect(symbolsOf(many)).toHaveLength(200);
  });

  it('shows an engine without a final row as not final, with its attempts', () => {
    const view = engineOf('rspamd', [row({ attempt: 2, completedAt: at(3) }), row({})]);
    expect(view).toMatchObject({
      engine: 'rspamd',
      final: false,
      outcome: null,
      score: null,
      reasonCodes: [],
      symbols: [],
      completedAt: null,
      engineVersion: '3.12.1',
    });
    expect(view.attempts.map((a) => a.attempt)).toEqual([1, 2]);
  });

  it('uses the final row as the result and converts decimals', () => {
    const final = row({
      attempt: 2,
      isFinal: true,
      outcome: 'suspicious',
      score: new Prisma.Decimal('4.25'),
      requiredScore: new Prisma.Decimal('15'),
      action: 'no action',
      reasonCodes: ['spam.suspicious_score'],
      errorCode: null,
      settingsVersion: 'rspamd-map/1;p=0123456789ab;t=2',
      evidence: { signals: [{ name: 'BAYES_SPAM', score: 3, options: ['99%'] }] },
      completedAt: at(4),
    });
    const view = engineOf('rspamd', [row({}), final]);
    expect(view).toMatchObject({
      final: true,
      outcome: 'suspicious',
      score: 4.25,
      requiredScore: 15,
      reasonCodes: ['spam.suspicious_score'],
      symbols: [{ name: 'BAYES_SPAM', score: 3, options: ['99%'] }],
      settingsVersion: 'rspamd-map/1;p=0123456789ab;t=2',
      completedAt: at(4).toISOString(),
    });
    expect(view.attempts.map((a) => [a.attempt, a.outcome, a.errorCode])).toEqual([
      [1, 'error', 'unavailable'],
      [2, 'suspicious', null],
    ]);
  });

  it('withholds the attachment engine timing and rounds its times to the second (cross-tenant cache)', () => {
    const ms = (s: number, milli: number) => new Date(at(s).getTime() + milli);
    const rows = [
      row({ engine: 'attachment', durationMs: 7, completedAt: ms(2, 345) }),
      row({
        engine: 'attachment',
        attempt: 2,
        isFinal: true,
        outcome: 'clean',
        errorCode: null,
        durationMs: 4,
        completedAt: ms(5, 999),
      }),
    ];
    const view = engineOf('attachment', rows);
    expect(view).toMatchObject({ durationMs: null, completedAt: at(5).toISOString() });
    expect(view.attempts).toEqual([
      expect.objectContaining({ attempt: 1, durationMs: null, at: at(2).toISOString() }),
      expect.objectContaining({ attempt: 2, durationMs: null, at: at(5).toISOString() }),
    ]);
    // Other engines keep their exact values.
    const rspamd = engineOf('rspamd', [row({ completedAt: ms(2, 345), durationMs: 7 })]);
    expect(rspamd.attempts[0]).toMatchObject({ durationMs: 7, at: ms(2, 345).toISOString() });
  });

  it('builds a round from its own rows only, engines in catalog order, auth of the first engine', () => {
    const auth: AuthResultRow = {
      scanId: 2n,
      engine: 'rspamd',
      spf: 'pass',
      spfDomain: 'clean.scan.test',
      dkim: 'pass',
      dkimSignatures: [
        { domain: 'clean.scan.test', result: 'pass', selector: 'eg2026' },
        { garbage: true },
      ],
      dmarc: 'pass',
      dmarcPolicy: 'reject',
      dmarcDomain: 'clean.scan.test',
      arc: 'none',
    };
    const view = roundOf(
      scan(2n, 1, {
        status: 'completed',
        scanVerdict: 'clean',
        reasonCodes: ['clean.below_threshold'],
      }),
      [
        row({ scanId: 2n, engine: 'zzz_future', isFinal: true, outcome: 'clean' }),
        row({ scanId: 2n, isFinal: true, outcome: 'clean' }),
        row({ scanId: 1n, isFinal: true, outcome: 'spam' }),
      ],
      [auth, { ...auth, scanId: 1n, spf: 'fail' }],
    );
    expect(view).toMatchObject({
      round: 1,
      scanKind: 'rescan',
      status: 'completed',
      verdict: 'clean',
      reasonCodes: ['clean.below_threshold'],
      requiredEngines: ['rspamd'],
      auth: {
        spf: 'pass',
        dkimSignatures: [{ domain: 'clean.scan.test', result: 'pass', selector: 'eg2026' }],
      },
    });
    expect(view.engines.map((e) => [e.engine, e.outcome])).toEqual([
      ['rspamd', 'clean'],
      ['zzz_future', 'clean'],
    ]);
    expect(roundOf(scan(3n, 2), [], []).auth).toBeNull();
  });

  it('round-trips the cursor and refuses anything else', () => {
    for (const round of [0, 1, 42, 65_535]) {
      expect(decodeScanCursor(encodeScanCursor(round))).toBe(round);
    }
    for (const bad of ['bogus', Buffer.from('r65536').toString('base64url'), 'cjAx', '']) {
      expect(() => decodeScanCursor(bad)).toThrow(BadRequestException);
    }
  });
});

describe('attachment results (step 4.2 A16)', () => {
  const base: AttachmentResultRow = {
    scanId: 7n,
    attachmentId: 900n,
    partIndex: 2,
    sha256: 'b'.repeat(64),
    sizeBytes: 1024,
    detectedType: 'zip',
    typeFamily: 'archive',
    typeMismatch: false,
    verdict: 'suspicious',
    reasonCodes: ['archive.encrypted', 'not.a.code', 7],
    clamavSignature: null,
    clamavEngineVersion: '1.4.6',
    clamavDbVersion: 28173,
    yaraBundleId: 'yara-1-462fab6e5cc4',
    yaraMatches: [{ rule: 'EG_Test_Marker_Medium', severity: 'medium', scope: '0' }],
    archive: {
      format: 'zip',
      supported: true,
      entries: 1,
      depthReached: 1,
      decompressedBytes: 10,
      maxRatio: 1.5,
      encrypted: true,
      findings: [{ path: '0', type: 'pdf', reasonCodes: ['archive.encrypted'] }],
    },
    knownHashSeverity: 'medium',
  };

  it('maps a row with its part metadata and sandbox submission; unknown codes are dropped', () => {
    const view = attachmentOf(
      base,
      { partIndex: 2, filename: 'a.zip', declaredContentType: 'application/zip' },
      { id: 55n, scanId: 7n, attachmentId: 900n, status: 'pending' },
    );
    expect(view).toMatchObject({
      partIndex: 2,
      filename: 'a.zip',
      reasonCodes: ['archive.encrypted'],
      clamav: { signature: null, engineVersion: '1.4.6', dbVersion: 28173 },
      yara: { bundleId: 'yara-1-462fab6e5cc4', matches: [{ rule: 'EG_Test_Marker_Medium' }] },
      archive: { format: 'zip', encrypted: true },
      knownHash: { severity: 'medium', family: null },
      sandbox: { submissionId: '55', status: 'pending' },
    });
    // The cross-tenant content cache outcome and the per-file timing are never shown.
    expect(view).not.toHaveProperty('cache');
    expect(view).not.toHaveProperty('durationMs');
  });

  it('shows malformed stored JSON as null, never raw', () => {
    const view = attachmentOf(
      {
        ...base,
        yaraMatches: [{ rule: 'bad rule name', severity: 'x' }],
        archive: { format: 'zip', entryNames: ['secret.txt'] },
        clamavDbVersion: null,
      },
      undefined,
      undefined,
    );
    expect(view).toMatchObject({
      yara: null,
      archive: null,
      clamav: null,
      filename: null,
      sandbox: null,
    });
    expect(JSON.stringify(view)).not.toContain('secret.txt');
  });

  it('attaches the rows of the round only, by part index, to the attachment engine entry', () => {
    const rows = [
      { ...base, partIndex: 3, attachmentId: 901n },
      { ...base, partIndex: 1, attachmentId: 902n },
      { ...base, scanId: 8n },
    ];
    expect(
      attachmentsOf(7n, { results: rows, parts: [], submissions: [] }).map((a) => a.partIndex),
    ).toEqual([1, 3]);
  });
});

describe('url results (step 4.3 U16)', () => {
  const URL_SHA = 'b'.repeat(64);
  const messageUrl = (overrides: Partial<MessageUrlRow> = {}): MessageUrlRow => ({
    urlSeq: 0,
    url: 'https://clean-site.test/landing#top',
    urlSha256: URL_SHA,
    host: 'clean-site.test',
    unicodeHost: null,
    registrableDomain: 'clean-site.test',
    hostKind: 'domain',
    flags: ['url.idn', 'url.none', 'bogus'],
    sources: { html_href: 2, text: 1, nonsense: 4 },
    ...overrides,
  });
  const result = (overrides: Partial<UrlResultRow> = {}): UrlResultRow => ({
    scanId: 5n,
    urlSeq: 0,
    urlSha256: URL_SHA,
    verdict: 'suspicious',
    reasonCodes: ['url.redirect_blocked_internal', 'engine.error'],
    reputation: [
      {
        provider: 'local_feed',
        version: 'local_feed/1',
        kind: 'domain',
        status: 'listed',
        category: 'phishing',
        severity: 'high',
        cache: 'none',
      },
      {
        provider: 'dnsbl',
        version: 'dnsbl/1;x',
        kind: 'url',
        status: 'clear',
        category: null,
        cache: 'hit',
      },
      { bad: true },
    ],
    lookalike: [
      { rule: 'L1', targetKind: 'brand', targetDomain: 'paypal.com', score: 1, distance: 0 },
      { rule: 'L6', targetKind: null, targetDomain: null, score: 0, distance: null },
    ],
    fetchStatus: 'blocked',
    fetchError: 'loopback',
    hopCount: 1,
    redirectChain: [
      { host: 'short-link.test', port: 80, status: 302, kind: 'initial', blocked: null },
      { host: '127.0.0.1', port: 80, status: null, kind: 'http', blocked: 'loopback' },
    ],
    finalUrl: null,
    finalStatus: null,
    landing: null,
    rewritten: true,
    ...overrides,
  });
  const inputs = (over: Partial<UrlInputs> = {}): UrlInputs => ({
    urls: [messageUrl()],
    results: [result()],
    rewrites: [],
    inspections: [],
    clicks: [],
    ...over,
  });

  it('maps a URL: picked reputation without cache, chain without ports, codes filtered', () => {
    const [view] = urlsOf(5n, inputs());
    expect(view).toEqual({
      urlSeq: 0,
      url: 'https://clean-site.test/landing#top',
      host: 'clean-site.test',
      unicodeHost: null,
      registrableDomain: 'clean-site.test',
      hostKind: 'domain',
      sources: { html_href: 2, text: 1 },
      flags: ['url.idn'],
      verdict: 'suspicious',
      reasonCodes: ['url.redirect_blocked_internal'],
      reputation: [
        { provider: 'local_feed', kind: 'domain', status: 'listed', category: 'phishing' },
        { provider: 'dnsbl', kind: 'url', status: 'clear', category: null },
      ],
      lookalike: [
        { rule: 'L1', targetKind: 'brand', targetDomain: 'paypal.com', score: 1 },
        { rule: 'L6', targetKind: null, targetDomain: null, score: 0 },
      ],
      fetch: {
        status: 'blocked',
        error: null,
        hops: 1,
        chain: [
          { host: 'short-link.test', status: 302, kind: 'initial', blocked: null },
          { host: '127.0.0.1', status: null, kind: 'http', blocked: 'loopback' },
        ],
        finalUrl: null,
        finalStatus: null,
      },
      landing: null,
      dynamic: null,
      rewritten: true,
      clicks: { total: 0, lastDecision: null, lastAt: null },
    });
    expect(JSON.stringify(view)).not.toMatch(/cache|durationMs|distance|severity/);
  });

  it('adds landing, dynamic inspection (eleven signal keys) and clicks rounded to the second', () => {
    const [view] = urlsOf(
      5n,
      inputs({
        results: [
          result({
            fetchStatus: 'completed',
            fetchError: null,
            landing: {
              passwordFields: 1,
              forms: 1,
              crossOriginFormAction: true,
              formActionHosts: ['collector-site.test'],
              titleBrandMatches: [],
            },
          }),
        ],
        inspections: [
          {
            scanId: 5n,
            urlSeq: 0,
            urlSha256: URL_SHA,
            status: 'completed',
            verdict: 'malicious',
            reasonCodes: ['url.dynamic_phishing'],
            signals: {
              passwordFields: 1,
              forms: 1,
              crossOriginFormAction: false,
              formActionHosts: [],
              downloadAttempted: false,
              blockedRequests: 2,
              requests: 9,
              bytes: 1000,
              titleBrandMatches: ['paypal'],
              jsRedirect: true,
              dialogs: 0,
              navigations: [{ host: 'x.test' }],
            },
          },
          { ...({} as UrlInspectionRow), scanId: 6n, urlSeq: 0 },
        ],
        clicks: [
          {
            urlSeq: 0,
            total: 3,
            lastDecision: 'blocked',
            lastAt: new Date('2026-11-05T08:00:09.987Z'),
          },
        ],
      }),
    );
    expect(view!.landing).toEqual({
      passwordFields: 1,
      forms: 1,
      crossOriginFormAction: true,
      titleBrandMatches: [],
    });
    expect(view!.fetch).toMatchObject({ status: 'completed', error: null });
    expect(view!.dynamic).toEqual({
      status: 'completed',
      verdict: 'malicious',
      reasonCodes: ['url.dynamic_phishing'],
      signals: expect.objectContaining({ blockedRequests: 2, jsRedirect: true }),
    });
    expect(view!.dynamic!.signals).not.toHaveProperty('navigations');
    expect(view!.clicks).toEqual({
      total: 3,
      lastDecision: 'blocked',
      lastAt: '2026-11-05T08:00:09.000Z',
    });
  });

  it('drops results of other rounds and results whose URL row is missing or another URL', () => {
    const views = urlsOf(
      5n,
      inputs({
        urls: [messageUrl(), messageUrl({ urlSeq: 1, urlSha256: 'c'.repeat(64) })],
        results: [result({ urlSeq: 1 }), result({ urlSeq: 2 }), result({ scanId: 6n }), result()],
      }),
    );
    expect(views.map((v) => v.urlSeq)).toEqual([0]);
  });

  it('maps the round rewrite (unknown skip reasons shown as error) and times to the second', () => {
    const expiresAt = new Date('2026-12-05T08:00:00.456Z');
    expect(
      rewriteOf(
        5n,
        inputs({
          rewrites: [
            {
              scanId: 5n,
              lifecycleRound: 0,
              status: 'rewritten',
              skipReason: null,
              linksRewritten: 3,
              partsRewritten: 2,
              dkimSigned: true,
              expiresAt,
            },
          ],
        }),
      ),
    ).toEqual({
      status: 'rewritten',
      skipReason: null,
      linksRewritten: 3,
      partsRewritten: 2,
      dkimSigned: true,
      expiresAt: '2026-12-05T08:00:00.000Z',
    });
    const skipped = (skipReason: string) =>
      rewriteOf(
        5n,
        inputs({
          rewrites: [
            {
              scanId: 5n,
              lifecycleRound: 0,
              status: 'skipped',
              skipReason,
              linksRewritten: 0,
              partsRewritten: 0,
              dkimSigned: false,
              expiresAt: null,
            },
          ],
        }),
      );
    expect(skipped('signed_smime')!.skipReason).toBe('signed_smime');
    expect(skipped('weird')!.skipReason).toBe('error');
    expect(rewriteOf(9n, inputs())).toBeNull();
  });

  it('withholds the url engine timing and attaches urls and rewrite to its entry', () => {
    const final = row({
      scanId: 5n,
      engine: 'url',
      outcome: 'suspicious',
      reasonCodes: ['url.redirect_blocked_internal'],
      errorCode: null,
      durationMs: 1234,
      isFinal: true,
      completedAt: new Date('2026-11-05T08:00:03.789Z'),
    });
    const view = engineOf('url', [final]);
    expect(view.durationMs).toBeNull();
    expect(view.completedAt).toBe('2026-11-05T08:00:03.000Z');
    expect(view.attempts[0]).toMatchObject({ durationMs: null, at: '2026-11-05T08:00:03.000Z' });
    const round = roundOf(scan(5n, 0), [final, row({ scanId: 5n })], [], undefined, inputs());
    const urlEntry = round.engines.find((e) => e.engine === 'url')!;
    expect(urlEntry.urls).toHaveLength(1);
    expect(urlEntry.rewrite).toBeNull();
    expect(round.engines.find((e) => e.engine === 'rspamd')).not.toHaveProperty('urls');
  });
});
