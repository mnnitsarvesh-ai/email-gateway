import type { FetchResult, LookalikeResult, ReputationLookup } from '@email-gateway/url-security';
import { describe, expect, it } from 'vitest';
import {
  answersByItem,
  answersFor,
  assignSeqs,
  chainItems,
  extraPartKind,
  hashPrefix,
  mergeLookalike,
  parseComplete,
  rewriteObjectKey,
  selectExtraParts,
  staticRisk,
  storedFetch,
  storedLookalike,
  storedReputation,
} from './url-rows';
import type { UrlAttachmentRow } from './url-store';

const noLookalike: LookalikeResult = {
  findings: [],
  mixedScript: false,
  idn: false,
  highConfidence: false,
  codes: [],
};

const answer = (over: Partial<ReputationLookup>): ReputationLookup => ({
  kind: 'domain',
  value: 'a.test',
  status: 'clear',
  category: null,
  severity: null,
  detail: null,
  provider: 'dnsbl',
  version: 'dnsbl/1;x',
  cache: 'miss',
  ...over,
});

const attachment = (partIndex: number, over: Partial<UrlAttachmentRow> = {}): UrlAttachmentRow => ({
  partIndex,
  filename: null,
  declaredContentType: 'application/pdf',
  detectedContentType: 'application/pdf',
  sizeBytes: 100,
  sha256: 'a'.repeat(64),
  objectKey: `org/7/part/2026/11/05/55/${String(partIndex)}.att`,
  ...over,
});

describe('content completeness (U4 E1)', () => {
  it('is complete only for final parses without a body or structural limit', () => {
    expect(parseComplete('parsed', [])).toBe(true);
    expect(parseComplete('parsed_with_defects', [])).toBe(true);
    expect(parseComplete('parse_limit_exceeded', ['attachment_count', 'attachment_size'])).toBe(
      true,
    );
    for (const limit of [
      'body_size',
      'message_size',
      'nesting_depth',
      'part_count',
      'header_count',
      'header_line_length',
      'header_block_size',
      'header_future_limit',
      'parse_timeout',
      'decoded_ratio',
      'total_decoded_size',
    ]) {
      expect(parseComplete('parse_limit_exceeded', [limit]), limit).toBe(false);
    }
    expect(parseComplete('parsing', [])).toBe(false);
    expect(parseComplete('parse_failed', [])).toBe(false);
  });
});

describe('extra parts (U4)', () => {
  it('classifies text/html attachments by detected/declared type or extension', () => {
    expect(
      extraPartKind({
        detectedContentType: 'text/html',
        declaredContentType: null,
        filename: null,
      }),
    ).toBe('html');
    expect(
      extraPartKind({
        detectedContentType: 'application/octet-stream',
        declaredContentType: 'text/plain; charset=x',
        filename: null,
      }),
    ).toBe('text');
    expect(
      extraPartKind({
        detectedContentType: null,
        declaredContentType: null,
        filename: 'Invoice.SHTML',
      }),
    ).toBe('html');
    expect(
      extraPartKind({
        detectedContentType: null,
        declaredContentType: null,
        filename: 'notes.txt',
      }),
    ).toBe('text');
    expect(
      extraPartKind({
        detectedContentType: 'application/xhtml+xml',
        declaredContentType: null,
        filename: null,
      }),
    ).toBe('html');
    expect(
      extraPartKind({
        detectedContentType: 'application/pdf',
        declaredContentType: 'application/pdf',
        filename: 'a.pdf',
      }),
    ).toBeNull();
  });

  it('selects stored parts within the size bound, at most N, in part order', () => {
    const rows = [
      attachment(1, { declaredContentType: 'text/html' }),
      attachment(2),
      attachment(3, { declaredContentType: 'text/plain', objectKey: null }),
      attachment(4, { declaredContentType: 'text/plain', sizeBytes: 5_000 }),
      attachment(5, { declaredContentType: 'text/plain' }),
      attachment(6, { filename: 'b.htm' }),
    ];
    expect(selectExtraParts(rows, 5, 1_000).map((p) => [p.row.partIndex, p.kind])).toEqual([
      [1, 'html'],
      [5, 'text'],
      [6, 'html'],
    ]);
    expect(selectExtraParts(rows, 1, 1_000).map((p) => p.row.partIndex)).toEqual([1]);
    expect(selectExtraParts(rows, 0, 1_000)).toEqual([]);
  });
});

describe('url_seq assignment (U3 step 3)', () => {
  it('keeps the seqs of earlier rounds and numbers new URLs after the maximum in order', () => {
    expect(assignSeqs(['a', 'b', 'c'], [])).toEqual({
      seqs: [0, 1, 2],
      isNew: [true, true, true],
      overflow: 0,
    });
    const existing = [
      { urlSeq: 0, urlSha256: 'a' },
      { urlSeq: 4, urlSha256: 'c' },
    ];
    expect(assignSeqs(['c', 'x', 'a', 'y'], existing)).toEqual({
      seqs: [4, 5, 0, 6],
      isNew: [false, true, false, true],
      overflow: 0,
    });
    // A rescan with the same URLs assigns the same seqs and nothing new.
    expect(assignSeqs(['c', 'a'], existing).isNew).toEqual([false, false]);
  });

  it('reports URLs whose seq would exceed 65 535', () => {
    const result = assignSeqs(
      ['n1', 'n2', 'old'],
      [
        { urlSeq: 65_534, urlSha256: 'z' },
        { urlSeq: 3, urlSha256: 'old' },
      ],
    );
    expect(result).toEqual({ seqs: [65_535, null, 3], isNew: [true, false, false], overflow: 1 });
  });
});

describe('static risk (U9) and lookalike merging (U10)', () => {
  it('counts static S-rule signals and non-clear answers; brand TLD variants are informational', () => {
    expect(
      staticRisk({ flags: [], hostKind: 'domain', lookalike: noLookalike, reputation: [] }),
    ).toBe(0);
    expect(
      staticRisk({
        flags: ['url.userinfo', 'url.idn', 'url.text_mismatch'],
        hostKind: 'ipv4',
        lookalike: {
          ...noLookalike,
          mixedScript: true,
          findings: [
            {
              rule: 'L5',
              targetKind: 'brand',
              targetDomain: 'paypal.com',
              score: 0.6,
              distance: null,
            },
            {
              rule: 'L3',
              targetKind: 'brand',
              targetDomain: 'paypal.com',
              score: 0.8,
              distance: null,
            },
          ],
        },
        reputation: [
          answer({ status: 'error' }),
          answer({ status: 'clear' }),
          answer({ status: 'listed' }),
        ],
      }),
    ).toBe(2 + 1 + 1 + 1 + 2);
  });

  it('merges the final URL lookalike (top 5 by score, flags or-ed, unique per rule and target)', () => {
    const a: LookalikeResult = {
      findings: [
        { rule: 'L2', targetKind: 'brand', targetDomain: 'paypal.com', score: 0.8, distance: 1 },
      ],
      mixedScript: false,
      idn: true,
      highConfidence: false,
      codes: ['url.idn', 'url.lookalike_edit_distance'],
    };
    const b: LookalikeResult = {
      findings: [
        {
          rule: 'L1',
          targetKind: 'extra',
          targetDomain: 'examplebank.test',
          score: 1,
          distance: null,
        },
        { rule: 'L2', targetKind: 'brand', targetDomain: 'paypal.com', score: 0.7, distance: 2 },
      ],
      mixedScript: true,
      idn: false,
      highConfidence: true,
      codes: ['url.lookalike_homoglyph', 'url.mixed_script'],
    };
    expect(mergeLookalike(a, null)).toBe(a);
    const merged = mergeLookalike(a, b);
    expect(merged.findings.map((f) => [f.rule, f.score])).toEqual([
      ['L1', 1],
      ['L2', 0.8],
    ]);
    expect(merged).toMatchObject({ mixedScript: true, idn: true, highConfidence: true });
    expect(merged.codes).toEqual([
      'url.idn',
      'url.lookalike_edit_distance',
      'url.lookalike_homoglyph',
      'url.mixed_script',
    ]);
  });
});

describe('stored JSON columns (U16, §3)', () => {
  it('lookalike: findings, then L4/L6 markers, at most 5; null when nothing', () => {
    expect(storedLookalike(noLookalike)).toBeNull();
    const stored = storedLookalike({
      ...noLookalike,
      mixedScript: true,
      idn: true,
      findings: Array.from({ length: 4 }, (_, i) => ({
        rule: 'L3' as const,
        targetKind: 'brand' as const,
        targetDomain: `b${String(i)}.com`,
        score: 0.8,
        distance: null,
      })),
    })!;
    expect(stored).toHaveLength(5);
    expect(stored.at(-1)).toEqual({
      rule: 'L4',
      targetKind: null,
      targetDomain: null,
      score: 1,
      distance: null,
    });
  });

  it('reputation: listed first, then errors, then clear, at most 12, with the internal cache flag', () => {
    const answers = [
      answer({ status: 'clear', value: 'c1' }),
      answer({ status: 'error', value: 'e1', detail: 'timeout' }),
      answer({ status: 'listed', value: 'l1', category: 'phishing', severity: 'high' }),
      ...Array.from({ length: 12 }, (_, i) => answer({ value: `c${String(i + 2)}` })),
    ];
    const stored = storedReputation(answers);
    expect(stored).toHaveLength(12);
    expect(stored.slice(0, 3).map((a) => a.status)).toEqual(['listed', 'error', 'clear']);
    expect(stored[0]).toEqual({
      provider: 'dnsbl',
      version: 'dnsbl/1;x',
      kind: 'domain',
      status: 'listed',
      category: 'phishing',
      severity: 'high',
      cache: 'miss',
    });
    // Never the detail or the looked-up value.
    expect(JSON.stringify(stored)).not.toContain('l1');
  });

  it('indexes answers by item', () => {
    const index = answersByItem([
      answer({ kind: 'url', value: 'http://a.test/' }),
      answer({ kind: 'url', value: 'http://a.test/', provider: 'local_feed' }),
      answer({ kind: 'domain', value: 'a.test' }),
    ]);
    expect(answersFor(index, [{ kind: 'url', value: 'http://a.test/' }])).toHaveLength(2);
    expect(answersFor(index, [{ kind: 'ip', value: '1.2.3.4' }])).toEqual([]);
  });

  const fetchResult = (over: Partial<FetchResult> = {}): FetchResult => ({
    status: 'completed',
    error: null,
    blockedReason: null,
    hops: [
      { host: 'short.test', port: null, status: 301, kind: 'initial', blocked: null },
      { host: '203.0.113.10', port: null, status: 302, kind: 'http', blocked: null },
      { host: 'final.test', port: 8443, status: 200, kind: 'http', blocked: null },
    ],
    finalUrl: 'https://final.test:8443/page?q=1#frag',
    finalStatus: 200,
    landing: {
      passwordFields: 1,
      forms: 1,
      crossOriginFormAction: true,
      formActionHosts: ['x.test'],
      titleBrandMatches: [],
    },
    durationMs: 12,
    ...over,
  });

  it('fetch: chain hosts only, redirect count, final URL columns, landing counts', () => {
    expect(storedFetch(null)).toMatchObject({
      fetchStatus: 'not_attempted',
      hopCount: 0,
      redirectChain: null,
    });
    const stored = storedFetch(fetchResult());
    expect(stored).toMatchObject({
      fetchStatus: 'completed',
      fetchError: null,
      hopCount: 2,
      finalUrl: 'https://final.test:8443/page?q=1#frag',
      finalHost: 'final.test',
      finalStatus: 200,
      landing: { passwordFields: 1, crossOriginFormAction: true },
    });
    expect(stored.finalUrlSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(stored.redirectChain).toEqual([
      { host: 'short.test', port: null, status: 301, kind: 'initial', blocked: null },
      { host: '203.0.113.10', port: null, status: 302, kind: 'http', blocked: null },
      { host: 'final.test', port: 8443, status: 200, kind: 'http', blocked: null },
    ]);
    expect(storedFetch(fetchResult({ finalStatus: 999 })).finalStatus).toBeNull();
    const many = fetchResult({
      hops: Array.from({ length: 12 }, (_, i) => ({
        host: `h${String(i)}.test`,
        port: null,
        status: 302,
        kind: 'http' as const,
        blocked: null,
      })),
    });
    expect(storedFetch(many).redirectChain).toHaveLength(10);
  });

  it('chain items: the final URL and the hosts of later hops (blocked hops excluded)', () => {
    const items = chainItems(
      fetchResult({
        hops: [
          { host: 'short.test', port: null, status: 301, kind: 'initial', blocked: null },
          { host: '203.0.113.10', port: null, status: 302, kind: 'http', blocked: null },
          { host: '10.0.0.5', port: null, status: null, kind: 'http', blocked: 'private' },
        ],
        finalUrl: 'http://final.test/x',
      }),
    );
    expect(items).toEqual([
      { kind: 'url', value: 'http://final.test/x' },
      { kind: 'domain', value: 'final.test' },
      { kind: 'ip', value: '203.0.113.10' },
    ]);
  });

  it('rewrite object keys: org prefix, UTC date of received_at, round and attempt suffix', () => {
    expect(rewriteObjectKey(7n, 55n, new Date('2026-01-02T23:30:00-05:00'), 2, 'abc')).toBe(
      'org/7/rewrite/2026/01/03/55/r2-abc.eml',
    );
    expect(hashPrefix('0123456789abcdef'.repeat(4))).toBe('0123456789ab');
  });
});
