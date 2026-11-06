import type { PrismaClient } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { InconsistentUrlReadError, PrismaUrlStore, TtlLru } from './url-store';

const MESSAGE = 55n;
const ORG = 7n;
const AT = new Date('2026-11-05T10:00:00.123Z');
const SHA = (c: string) => c.repeat(64);

const parseRow = (over: Record<string, unknown> = {}) => ({
  messageId: MESSAGE,
  receivedAt: new Date(AT),
  organizationId: ORG,
  status: 'parsed',
  limitsExceeded: '["attachment_count"]',
  attachmentCount: 1,
  textBodyObjectKey: 'org/7/part/2026/11/05/55/1.text',
  textBodySha256: SHA('a'),
  textBodySizeBytes: 10,
  textBodyCharset: 'utf-8',
  htmlBodyObjectKey: null,
  htmlBodySha256: null,
  htmlBodySizeBytes: null,
  htmlBodyCharset: null,
  structure: [
    { index: 0, path: '0', contentType: 'Multipart/Mixed', kind: 'container' },
    { index: 1, path: '0.1', contentType: 'text/plain', charset: 'iso-8859-1', kind: 'text' },
  ],
  ...over,
});

interface Fake {
  parse?: unknown;
  attachments?: unknown[];
  urls?: unknown[];
  domains?: unknown[];
  indicators?: unknown[];
  calls: Record<string, unknown[]>;
}

function store(fake: Fake, now?: () => Date): PrismaUrlStore {
  const record = (name: string) => (args: unknown) => {
    (fake.calls[name] ??= []).push(args);
  };
  const prisma = {
    emailMessageParse: {
      findFirst: (a: unknown) => (record('parse')(a), Promise.resolve(fake.parse ?? null)),
    },
    emailAttachment: {
      findMany: (a: unknown) => (record('attachments')(a), Promise.resolve(fake.attachments ?? [])),
    },
    messageUrl: { findMany: (a: unknown) => (record('urls')(a), Promise.resolve(fake.urls ?? [])) },
    domain: {
      findMany: (a: unknown) => (record('domains')(a), Promise.resolve(fake.domains ?? [])),
    },
    threatIndicator: {
      findMany: (a: unknown) => (record('feed')(a), Promise.resolve(fake.indicators ?? [])),
    },
  } as unknown as PrismaClient;
  return new PrismaUrlStore(prisma, now ? { now } : {});
}

const inconsistent = (read: string): unknown =>
  expect.objectContaining({ name: 'InconsistentUrlReadError', read }) as unknown;

describe('url store reads (U3 step 1, echo checks, step 4.2 §6)', () => {
  it('loads the parse row with bodies and structure, scoped by the trusted envelope', async () => {
    const fake: Fake = { parse: parseRow(), calls: {} };
    const row = await store(fake).loadParse(MESSAGE, AT, ORG);
    expect(fake.calls.parse?.[0]).toMatchObject({
      where: { messageId: MESSAGE, receivedAt: AT, organizationId: ORG },
    });
    expect(row).toEqual({
      status: 'parsed',
      limitsExceeded: ['attachment_count'],
      attachmentCount: 1,
      textBody: {
        key: 'org/7/part/2026/11/05/55/1.text',
        sha256: SHA('a'),
        sizeBytes: 10,
        charset: 'utf-8',
      },
      htmlBody: { key: null, sha256: null, sizeBytes: null, charset: null },
      structure: [
        { index: 0, contentType: 'multipart/mixed', charset: null },
        { index: 1, contentType: 'text/plain', charset: 'iso-8859-1' },
      ],
    });
    expect(await store({ calls: {} }).loadParse(MESSAGE, AT, ORG)).toBeNull();
    expect(
      (await store({ parse: parseRow({ structure: 'nope' }), calls: {} }).loadParse(
        MESSAGE,
        AT,
        ORG,
      ))!.structure,
    ).toBeNull();
    expect(
      (await store({ parse: parseRow({ structure: [{ index: 0 }] }), calls: {} }).loadParse(
        MESSAGE,
        AT,
        ORG,
      ))!.structure,
    ).toBeNull();
  });

  it('a parse row of another message, organization or received_at is an inconsistent read', async () => {
    for (const over of [
      { messageId: 56n },
      { organizationId: 8n },
      { receivedAt: new Date(AT.getTime() + 1) },
    ]) {
      await expect(
        store({ parse: parseRow(over), calls: {} }).loadParse(MESSAGE, AT, ORG),
      ).rejects.toEqual(inconsistent('parse'));
    }
  });

  it('attachment rows: echo and strictly ascending part order', async () => {
    const row = (partIndex: number, over: Record<string, unknown> = {}) => ({
      messageId: MESSAGE,
      receivedAt: new Date(AT),
      organizationId: ORG,
      partIndex,
      filename: 'a.html',
      declaredContentType: 'text/html',
      detectedContentType: 'text/html',
      sizeBytes: 5,
      sha256: SHA('b'),
      objectKey: `org/7/part/2026/11/05/55/${String(partIndex)}.att`,
      ...over,
    });
    const ok = await store({ attachments: [row(2), row(3)], calls: {} }).loadAttachments(
      MESSAGE,
      AT,
      ORG,
      10,
    );
    expect(ok.map((r) => r.partIndex)).toEqual([2, 3]);
    await expect(
      store({ attachments: [row(3), row(2)], calls: {} }).loadAttachments(MESSAGE, AT, ORG, 10),
    ).rejects.toEqual(inconsistent('attachments'));
    await expect(
      store({ attachments: [row(2, { organizationId: 9n })], calls: {} }).loadAttachments(
        MESSAGE,
        AT,
        ORG,
        10,
      ),
    ).rejects.toBeInstanceOf(InconsistentUrlReadError);
  });

  it('message_urls of earlier rounds: echo, unique seqs and hashes', async () => {
    const row = (urlSeq: number, urlSha256: string, over: Record<string, unknown> = {}) => ({
      messageId: MESSAGE,
      receivedAt: new Date(AT),
      organizationId: ORG,
      urlSeq,
      urlSha256,
      ...over,
    });
    expect(
      await store({ urls: [row(0, SHA('a')), row(1, SHA('b'))], calls: {} }).loadMessageUrls(
        MESSAGE,
        AT,
        ORG,
      ),
    ).toEqual([
      { urlSeq: 0, urlSha256: SHA('a') },
      { urlSeq: 1, urlSha256: SHA('b') },
    ]);
    for (const urls of [
      [row(0, SHA('a')), row(1, SHA('a'))],
      [row(1, SHA('a')), row(1, SHA('b'))],
      [row(0, SHA('a'), { messageId: 1n })],
    ]) {
      await expect(store({ urls, calls: {} }).loadMessageUrls(MESSAGE, AT, ORG)).rejects.toEqual(
        inconsistent('message_urls'),
      );
    }
  });

  it('active tenant domains: echo, lower case, LRU for 60 s per organization', async () => {
    let now = new Date('2026-11-05T10:00:00Z');
    const fake: Fake = {
      domains: [{ organizationId: ORG, name: 'Example.COM', status: 'active' }],
      calls: {},
    };
    const s = store(fake, () => now);
    expect(await s.activeDomains(ORG)).toEqual(['example.com']);
    expect(await s.activeDomains(ORG)).toEqual(['example.com']);
    expect(fake.calls.domains).toHaveLength(1);
    expect(fake.calls.domains?.[0]).toMatchObject({
      where: { organizationId: ORG, status: 'active', deletedAt: null },
    });
    now = new Date(now.getTime() + 60_001);
    await s.activeDomains(ORG);
    expect(fake.calls.domains).toHaveLength(2);
    await expect(
      store({
        domains: [{ organizationId: 8n, name: 'x.com', status: 'active' }],
        calls: {},
      }).activeDomains(ORG),
    ).rejects.toEqual(inconsistent('domains'));
  });

  it('the local feed reads platform rows that are not expired, and echo-checks them', async () => {
    const now = new Date('2026-11-05T10:00:00Z');
    const hit = {
      orgScope: 0n,
      organizationId: null,
      indicatorType: 'domain',
      valueSha256: SHA('c'),
      severity: 'high',
      category: 'phishing',
      expiresAt: null,
    };
    const fake: Fake = { indicators: [hit], calls: {} };
    const s = store(fake, () => now);
    expect(await s.feedQuery('domain', [SHA('c'), SHA('d')], AbortSignal.timeout(1000))).toEqual([
      { valueSha256: SHA('c'), severity: 'high', category: 'phishing' },
    ]);
    expect(fake.calls.feed?.[0]).toEqual({
      where: {
        orgScope: 0n,
        indicatorType: 'domain',
        valueSha256: { in: [SHA('c'), SHA('d')] },
        OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
      },
      select: expect.any(Object),
    });
    expect(await s.feedQuery('url', [], AbortSignal.timeout(1000))).toEqual([]);
    for (const over of [
      { indicatorType: 'url' },
      { organizationId: 5n, orgScope: 5n },
      { valueSha256: SHA('e') },
      { expiresAt: new Date(now.getTime() - 1) },
    ]) {
      await expect(
        store({ indicators: [{ ...hit, ...over }], calls: {} }, () => now).feedQuery(
          'domain',
          [SHA('c')],
          AbortSignal.timeout(1000),
        ),
      ).rejects.toEqual(inconsistent('feed'));
    }
  });
});

describe('TtlLru', () => {
  it('expires entries and evicts the least recently used', () => {
    let now = 0;
    const lru = new TtlLru<string, number>(2, 100, () => now);
    lru.set('a', 1);
    lru.set('b', 2);
    expect(lru.get('a')).toBe(1);
    lru.set('c', 3);
    expect(lru.get('b')).toBeUndefined();
    expect(lru.get('a')).toBe(1);
    now = 101;
    expect(lru.get('a')).toBeUndefined();
    expect(lru.size).toBe(1);
  });
});
