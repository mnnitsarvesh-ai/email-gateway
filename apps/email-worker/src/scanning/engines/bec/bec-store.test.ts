import type { PrismaClient } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import {
  BEC_MAX_HEADERS,
  InconsistentBecReadError,
  PrismaBecStore,
  type BecReadScope,
} from './bec-store';

/**
 * Echo checks of the bec loaders (step 4.4 §6): every read selects its identifying columns and
 * a row of another message, organization, time, scan, scope or key is an
 * `InconsistentBecReadError` (the engine's retryable `inconsistent_read`), never data.
 */

const ORG = 7n;
const MSG = 70n;
const AT = new Date('2026-11-06T10:00:00.000Z');
const scope: BecReadScope = {
  organizationId: ORG,
  messageId: MSG,
  receivedAt: AT,
  scanId: 700n,
  round: 0,
};
const NOW = new Date('2026-11-06T12:00:00.000Z');

type Rows = Record<string, unknown>;

/** A Prisma stand-in answering every model call from `rows` (by model name). */
function fakePrisma(rows: Rows, calls: string[] = []): PrismaClient {
  const model = (name: string) => ({
    findFirst: () => {
      calls.push(`${name}.findFirst`);
      const value = rows[name];
      return Promise.resolve(Array.isArray(value) ? (value[0] ?? null) : (value ?? null));
    },
    findUnique: () => {
      calls.push(`${name}.findUnique`);
      return Promise.resolve(rows[name] ?? null);
    },
    findMany: () => {
      calls.push(`${name}.findMany`);
      return Promise.resolve((rows[name] as unknown[]) ?? []);
    },
  });
  return new Proxy({}, { get: (_, name: string) => model(name) }) as unknown as PrismaClient;
}

const store = (rows: Rows, calls?: string[], ttlMs = 30_000) =>
  new PrismaBecStore(
    fakePrisma(rows, calls),
    { executives: 500, vendors: 2000, trustedSenders: 1000, suppressions: 200 },
    { ttlMs, now: () => NOW },
  );

const read = async (promise: Promise<unknown>): Promise<string> => {
  try {
    await promise;
    return 'ok';
  } catch (error) {
    expect(error).toBeInstanceOf(InconsistentBecReadError);
    return (error as InconsistentBecReadError).read;
  }
};

const scanRow = {
  id: 700n,
  receivedAt: AT,
  messageId: MSG,
  organizationId: ORG,
  lifecycleRound: 0,
  scanKind: 'initial',
  requiredEngines: ['rspamd', 'url', 'bec'],
};

describe('PrismaBecStore echo checks (§6)', () => {
  it('round row: identity and round echo', async () => {
    expect(await store({ emailScan: scanRow }).loadRound(scope)).toEqual({
      round: 0,
      scanKind: 'initial',
      requiredEngines: ['rspamd', 'url', 'bec'],
    });
    expect(
      await read(store({ emailScan: { ...scanRow, organizationId: 8n } }).loadRound(scope)),
    ).toBe('scan');
    expect(
      await read(store({ emailScan: { ...scanRow, lifecycleRound: 1 } }).loadRound(scope)),
    ).toBe('scan');
    expect(
      await read(store({ emailScan: { ...scanRow, receivedAt: new Date(0) } }).loadRound(scope)),
    ).toBe('scan');
    expect(await store({}).loadRound(scope)).toBeNull();
  });

  it('dependency finals: scan, finality, engine and uniqueness', async () => {
    const final = {
      scanId: 700n,
      receivedAt: AT,
      messageId: MSG,
      organizationId: ORG,
      engine: 'rspamd',
      isFinal: true,
      outcome: 'clean',
    };
    expect(await store({ scanEngineResult: [final] }).loadFinals(scope, ['rspamd', 'url'])).toEqual(
      [{ engine: 'rspamd', outcome: 'clean' }],
    );
    for (const bad of [
      { ...final, scanId: 701n },
      { ...final, isFinal: false },
      { ...final, engine: 'attachment' },
    ]) {
      expect(
        await read(store({ scanEngineResult: [bad] }).loadFinals(scope, ['rspamd', 'url'])),
      ).toBe('finals');
    }
    expect(
      await read(store({ scanEngineResult: [final, final] }).loadFinals(scope, ['rspamd'])),
    ).toBe('finals');
  });

  it('auth row: scan and engine echo; unknown outcomes are dropped to null', async () => {
    const row = {
      scanId: 700n,
      receivedAt: AT,
      messageId: MSG,
      organizationId: ORG,
      engine: 'rspamd',
      spf: 'pass',
      spfDomain: 'x.test',
      dkim: 'weird',
      dkimSignatures: [{ domain: 'x.test', result: 'pass', selector: 's' }, { nope: 1 }],
      dmarc: null,
      dmarcPolicy: null,
      dmarcDomain: null,
      arc: null,
    };
    const auth = await store({ emailAuthResult: row }).loadAuth(scope, 'rspamd');
    expect(auth).toMatchObject({ spf: 'pass', dkim: null, dkimSignatures: [{ domain: 'x.test' }] });
    expect(
      await read(store({ emailAuthResult: { ...row, engine: 'url' } }).loadAuth(scope, 'rspamd')),
    ).toBe('auth');
    expect(
      await read(store({ emailAuthResult: { ...row, messageId: 71n } }).loadAuth(scope, 'rspamd')),
    ).toBe('auth');
  });

  it('url results: order, verdicts and the seq/hash join with message_urls', async () => {
    const result = (urlSeq: number, urlSha256: string) => ({
      scanId: 700n,
      receivedAt: AT,
      messageId: MSG,
      organizationId: ORG,
      urlSeq,
      urlSha256,
      verdict: 'malicious',
      reasonCodes: ['url.phishing_high_confidence'],
    });
    const url = (urlSeq: number, urlSha256: string) => ({
      messageId: MSG,
      receivedAt: AT,
      organizationId: ORG,
      urlSeq,
      urlSha256,
      host: 'phish-login.test',
      registrableDomain: 'phish-login.test',
    });
    expect(
      await store({ urlScanResult: [result(1, 'a')], messageUrl: [url(1, 'a')] }).loadUrlResults(
        scope,
      ),
    ).toEqual([
      {
        urlSeq: 1,
        verdict: 'malicious',
        reasonCodes: ['url.phishing_high_confidence'],
        host: 'phish-login.test',
        registrableDomain: 'phish-login.test',
      },
    ]);
    expect(
      await read(
        store({ urlScanResult: [result(1, 'a')], messageUrl: [url(1, 'b')] }).loadUrlResults(scope),
      ),
    ).toBe('urls');
    expect(
      await read(store({ urlScanResult: [result(2, 'a'), result(1, 'b')] }).loadUrlResults(scope)),
    ).toBe('urls');
    expect(
      await read(store({ urlScanResult: [result(1, 'a')], messageUrl: [] }).loadUrlResults(scope)),
    ).toBe('urls');
  });

  it('headers: identity and seq order; grouped by name in order', async () => {
    const h = (seq: number, name: string, value: string, messageId = MSG) => ({
      messageId,
      receivedAt: AT,
      organizationId: ORG,
      seq,
      name,
      value,
    });
    expect(
      await store({
        emailHeader: [
          h(0, 'From', 'a <a@x.test>'),
          h(1, 'Reply-To', 'b@y.test'),
          h(2, 'From', 'c@z.test'),
        ],
      }).loadHeaders(scope),
    ).toEqual({
      headers: { From: ['a <a@x.test>', 'c@z.test'], 'Reply-To': ['b@y.test'] },
      truncated: false,
    });
    // Exactly BEC_MAX_HEADERS rows are complete; one more (read as take + 1) is a truncated set
    // whose extra row is never used.
    const many = (n: number) =>
      Array.from({ length: n }, (_, i) => h(i, i === n - 1 ? 'Reply-To' : 'To', `r${i}@x.test`));
    const exact = await store({ emailHeader: many(BEC_MAX_HEADERS) }).loadHeaders(scope);
    expect(exact.truncated).toBe(false);
    expect(exact.headers['Reply-To']).toEqual([`r${BEC_MAX_HEADERS - 1}@x.test`]);
    const over = await store({ emailHeader: many(BEC_MAX_HEADERS + 1) }).loadHeaders(scope);
    expect(over.truncated).toBe(true);
    expect(over.headers['Reply-To']).toBeUndefined();
    expect(over.headers.To).toHaveLength(BEC_MAX_HEADERS);
    expect(
      await read(store({ emailHeader: [h(1, 'From', 'a'), h(0, 'To', 'b')] }).loadHeaders(scope)),
    ).toBe('headers');
    expect(await read(store({ emailHeader: [h(0, 'From', 'a', 99n)] }).loadHeaders(scope))).toBe(
      'headers',
    );
  });

  it('parse row and subject: identity echo; an absent message row is inconsistent', async () => {
    const parse = {
      messageId: MSG,
      receivedAt: AT,
      organizationId: ORG,
      status: 'parsed',
      limitsExceeded: ['body_size'],
      defects: '["stored_headers_truncated"]',
      textBodyObjectKey: 'org/7/part/t',
      textBodySha256: 'a'.repeat(64),
      textBodySizeBytes: 10,
      htmlBodyObjectKey: null,
      htmlBodySha256: null,
      htmlBodySizeBytes: null,
    };
    expect(await store({ emailMessageParse: parse }).loadParse(scope)).toMatchObject({
      status: 'parsed',
      limitsExceeded: ['body_size'],
      defects: ['stored_headers_truncated'],
      textBody: { key: 'org/7/part/t', sizeBytes: 10 },
    });
    expect(
      await read(store({ emailMessageParse: { ...parse, organizationId: 9n } }).loadParse(scope)),
    ).toBe('parse');
    expect(await store({}).loadParse(scope)).toBeNull();
    const message = { id: MSG, receivedAt: AT, organizationId: ORG, subject: 'Hello' };
    expect(await store({ emailMessage: message }).loadSubject(scope)).toBe('Hello');
    expect(await read(store({}).loadSubject(scope))).toBe('message');
    expect(await read(store({ emailMessage: { ...message, id: 1n } }).loadSubject(scope))).toBe(
      'message',
    );
  });

  it('tenant data: echo-checked, normalized, cached per organization for the TTL', async () => {
    const rows: Rows = {
      domain: [{ organizationId: ORG, name: 'AcmeCorp.test', status: 'active', deletedAt: null }],
      becExecutiveProfile: [
        {
          organizationId: ORG,
          publicId: 'e1',
          displayName: 'Anita Sharma',
          aliases: ['A Sharma'],
          knownAddresses: ['Anita@AcmeCorp.test'],
          enabled: true,
        },
      ],
      becVendorProfile: [],
      becTrustedSender: [
        {
          organizationId: ORG,
          publicId: 't1',
          kind: 'domain',
          value: 'Partner.test',
          expiresAt: null,
        },
      ],
      becSuppressionRule: [
        {
          organizationId: ORG,
          publicId: 's1',
          reasonCode: 'bec.content.urgency',
          senderScope: 'address',
          senderValue: 'Bob@Partner.test',
          expiresAt: new Date('2026-12-01T00:00:00Z'),
        },
      ],
      scanEngineSetting: {
        organizationId: ORG,
        engine: 'url',
        settings: { lookalike: { extraProtectedDomains: ['x.test'] } },
        version: 3,
      },
    };
    const calls: string[] = [];
    const s = store(rows, calls);
    const data = await s.tenantData(ORG);
    expect(data).toMatchObject({
      tenantDomains: ['acmecorp.test'],
      executives: [
        {
          publicId: 'e1',
          name: 'Anita Sharma',
          aliases: ['A Sharma'],
          knownAddresses: ['anita@acmecorp.test'],
        },
      ],
      trustedSenders: [{ kind: 'domain', value: 'partner.test' }],
      suppressions: [{ reasonCode: 'bec.content.urgency', senderValue: 'bob@partner.test' }],
      urlSettingsRow: { version: 3 },
    });
    await s.tenantData(ORG);
    expect(calls.filter((c) => c === 'domain.findMany')).toHaveLength(1);
    // TTL 0: reloaded every time.
    const uncached: string[] = [];
    const s0 = store(rows, uncached, 0);
    await s0.tenantData(ORG);
    await s0.tenantData(ORG);
    expect(uncached.filter((c) => c === 'domain.findMany')).toHaveLength(2);

    for (const [key, bad] of [
      [
        'becExecutiveProfile',
        [{ ...(rows.becExecutiveProfile as object[])[0], organizationId: 8n }],
      ],
      ['becExecutiveProfile', [{ ...(rows.becExecutiveProfile as object[])[0], enabled: false }]],
      [
        'becSuppressionRule',
        [
          {
            ...(rows.becSuppressionRule as object[])[0],
            expiresAt: new Date('2026-11-01T00:00:00Z'),
          },
        ],
      ],
      [
        'domain',
        [{ organizationId: ORG, name: 'x.test', status: 'pending_verification', deletedAt: null }],
      ],
      ['scanEngineSetting', { organizationId: ORG, engine: 'bec', settings: {}, version: 1 }],
    ] as const) {
      expect(await read(store({ ...rows, [key]: bad }).tenantData(ORG))).toBe('tenant');
    }
  });

  it('history: organization, scope and requested key echo; infra parsed for sender rows', async () => {
    const row = {
      organizationId: ORG,
      scope: 'sender',
      keyHash: 'a'.repeat(64),
      messageCount: 4,
      firstSeenAt: AT,
      lastSeenAt: AT,
      infra: [{ fp: '0123456789abcdef', count: 2, lastSeenAt: AT.toISOString() }, { bad: true }],
    };
    expect(
      await store({ becContactHistory: [row] }).loadHistory(ORG, 'sender', ['a'.repeat(64)]),
    ).toEqual([
      {
        keyHash: 'a'.repeat(64),
        row: {
          messageCount: 4,
          firstSeenAt: AT,
          lastSeenAt: AT,
          infra: [{ fp: '0123456789abcdef', count: 2, lastSeenAt: AT.toISOString() }],
        },
      },
    ]);
    expect(
      await read(store({ becContactHistory: [row] }).loadHistory(ORG, 'sender', ['b'.repeat(64)])),
    ).toBe('history');
    expect(
      await read(store({ becContactHistory: [row] }).loadHistory(ORG, 'pair', ['a'.repeat(64)])),
    ).toBe('history');
    expect(
      await read(
        store({ becContactHistory: [{ ...row, organizationId: 8n }] }).loadHistory(ORG, 'sender', [
          'a'.repeat(64),
        ]),
      ),
    ).toBe('history');
    expect(await store({}).loadHistory(ORG, 'pair', [])).toEqual([]);
  });
});
