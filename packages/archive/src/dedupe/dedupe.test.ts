import { createHash } from 'node:crypto';
import { Readable, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { BodyHasher, BodyHashState, bodySha256Of } from './body-hash';
import { dedupeMessageIdHash, headerFingerprint } from './fingerprint';
import { decideMerge, MERGE_ORDER_SKEW_MS, type MergeCandidate } from './merge';

const sha = (s: string | Buffer) => createHash('sha256').update(s).digest('hex');
const A1 = 'a'.repeat(64);
const B1 = 'B'.repeat(64);

describe('archive-dedupe/1 key', () => {
  it('hashes the label, organization and bare Message-ID', () => {
    expect(dedupeMessageIdHash(42, ' <id-1@example.com> ')).toBe(
      sha('archive-dedupe/1\u000042\u0000id-1@example.com'),
    );
    expect(dedupeMessageIdHash('42', 'id-1@example.com')).toBe(
      dedupeMessageIdHash(42n, '<id-1@example.com>'),
    );
    // Another organization never collides.
    expect(dedupeMessageIdHash(43, '<id-1@example.com>')).not.toBe(
      dedupeMessageIdHash(42, '<id-1@example.com>'),
    );
    expect(dedupeMessageIdHash(42, '<>')).toBeNull();
    expect(dedupeMessageIdHash(42, null)).toBeNull();
    expect(() => dedupeMessageIdHash(-1, '<a@b>')).toThrow(RangeError);
  });
});

describe('archive-fingerprint/1', () => {
  const block = (lines: string[]) => `${lines.join('\r\n')}\r\n\r\n`;
  const base = [
    'Message-ID: <q1@example.com>',
    'Date: Mon, 16 Nov 2026 10:15:00 +0000',
    'From: Alice <Alice@Example.com>',
    'To: Bob <bob@example.org>, carol@example.com',
    'Cc: dave@example.com',
    'Subject: Quarterly report',
  ];

  it('is the SHA-256 of the canonical JSON of date, from, to and attachments', () => {
    const fp = headerFingerprint({ headerBlock: block(base), attachmentSha256s: [B1, A1] });
    expect(fp).not.toBeNull();
    expect(fp!.messageId).toBe('q1@example.com');
    expect(fp!.canonical).toEqual({
      date: 1_794_824_100,
      from: 'alice@example.com',
      to: ['bob@example.org', 'carol@example.com', 'dave@example.com'],
      attachments: [A1, B1.toLowerCase()],
    });
    expect(fp!.fingerprint).toBe(
      sha(
        `{"attachments":["${A1}","${B1.toLowerCase()}"],"date":1794824100,"from":"alice@example.com","to":["bob@example.org","carol@example.com","dave@example.com"]}`,
      ),
    );
  });

  it('ignores case, order, folding, duplicates, other headers and the Date notation', () => {
    const a = headerFingerprint({ headerBlock: block(base), attachmentSha256s: [A1, B1] })!;
    const b = headerFingerprint({
      headerBlock: Buffer.from(
        block([
          'Received: from gateway.example.net',
          'subject: changed by the gateway [EXTERNAL]',
          'cc: DAVE@example.com,',
          '  bob@EXAMPLE.org',
          'to: carol@example.com',
          'date: Mon, 16 Nov 2026 11:15 +0100 (CET)',
          'from: alice@example.com',
          'message-id:   <q1@example.com>',
          'X-MS-Exchange-CrossTenant-Id: 11111111-2222-3333-4444-555555555555',
        ]).replace(/\r\n/g, '\n'),
      ),
      attachmentSha256s: [B1.toLowerCase(), A1],
    })!;
    expect(b.fingerprint).toBe(a.fingerprint);
  });

  it('changes with the date, sender, recipients or attachments', () => {
    const fp = (lines: string[], att: string[] = []) =>
      headerFingerprint({ headerBlock: block(lines), attachmentSha256s: att })!.fingerprint;
    const ref = fp(base);
    expect(fp(base.map((l) => l.replace('10:15:00', '10:15:01')))).not.toBe(ref);
    expect(fp(base.map((l) => l.replace('Alice@', 'Mallory@')))).not.toBe(ref);
    expect(fp(base.filter((l) => !l.startsWith('Cc')))).not.toBe(ref);
    expect(fp(base, [A1])).not.toBe(ref);
  });

  it.each([
    ['no Message-ID', base.filter((l) => !l.startsWith('Message-ID'))],
    ['empty Message-ID', base.map((l) => (l.startsWith('Message-ID') ? 'Message-ID: <>' : l))],
    ['no Date', base.filter((l) => !l.startsWith('Date'))],
    ['bad Date', base.map((l) => (l.startsWith('Date') ? 'Date: soon' : l))],
    ['no From', base.filter((l) => !l.startsWith('From'))],
    ['bad From', base.map((l) => (l.startsWith('From') ? 'From: nobody' : l))],
  ])('%s → null (no dedupe)', (_name, lines) => {
    expect(headerFingerprint({ headerBlock: block(lines), attachmentSha256s: [] })).toBeNull();
  });

  it('an attachment without a valid hash → null (fail-safe)', () => {
    expect(headerFingerprint({ headerBlock: block(base), attachmentSha256s: [null] })).toBeNull();
    expect(headerFingerprint({ headerBlock: block(base), attachmentSha256s: ['abc'] })).toBeNull();
  });

  it('reads only the header block', () => {
    const withBody = `${block(base)}From: body@example.org\r\n`;
    expect(headerFingerprint({ headerBlock: withBody, attachmentSha256s: [] })!.fingerprint).toBe(
      headerFingerprint({ headerBlock: block(base), attachmentSha256s: [] })!.fingerprint,
    );
  });
});

describe('BodyHasher', () => {
  it.each([
    ['CRLF CRLF', 'A: 1\r\nB: 2\r\n\r\nbody\r\n', 'body\r\n'],
    ['LF LF', 'A: 1\nB: 2\n\nbody\n\nmore', 'body\n\nmore'],
    ['first separator wins', 'A: 1\n\n\r\n\r\nrest', '\r\n\r\nrest'],
    ['CRLF first', 'A: 1\r\n\r\n\n\nrest', '\n\nrest'],
    ['no separator', 'A: 1\r\nB: 2\r\n', ''],
    ['empty body', 'A: 1\r\n\r\n', ''],
    ['LF CRLF is not a separator', 'A: 1\n\r\nB\n\nbody', 'body'],
    ['separator at the start', '\n\nbody', 'body'],
  ])('%s', (_name, message, body) => {
    expect(bodySha256Of(Buffer.from(message))).toBe(sha(body));
  });

  it('property: the hash does not depend on chunk boundaries', () => {
    const alphabet = fc.constantFrom(...'\r\n\r\n\nab: '.split(''));
    fc.assert(
      fc.property(
        fc.array(alphabet, { maxLength: 60 }).map((a) => a.join('')),
        fc.array(fc.nat(), { maxLength: 20 }),
        (text, cuts) => {
          const message = Buffer.from(text, 'latin1');
          const whole = bodySha256Of(message);
          const positions = [...new Set(cuts.map((c) => c % (message.length + 1)))].sort(
            (x, y) => x - y,
          );
          const state = new BodyHashState();
          let prev = 0;
          for (const p of [...positions, message.length]) {
            state.update(message.subarray(prev, p));
            prev = p;
          }
          // Reference: the bytes after whichever separator is completed first.
          const crlf = text.indexOf('\r\n\r\n');
          const lflf = text.indexOf('\n\n');
          const candidates = [...(crlf < 0 ? [] : [crlf + 4]), ...(lflf < 0 ? [] : [lflf + 2])];
          const firstEnd = candidates.length === 0 ? -1 : Math.min(...candidates);
          const reference = firstEnd < 0 ? sha('') : sha(message.subarray(firstEnd));
          return state.digest() === whole && whole === reference;
        },
      ),
      { numRuns: 2000 },
    );
  });

  it('passes bytes through unchanged and exposes the hash after the end', async () => {
    const message = Buffer.from('Subject: x\r\n\r\nhello world\r\n');
    const hasher = new BodyHasher();
    const out: Buffer[] = [];
    await pipeline(
      Readable.from([message.subarray(0, 13), message.subarray(13)]),
      hasher,
      new Writable({
        write(c: Buffer, _e, cb) {
          out.push(c);
          cb();
        },
      }),
    );
    expect(Buffer.concat(out).equals(message)).toBe(true);
    expect(hasher.bodySha256).toBe(sha('hello world\r\n'));
    expect(hasher.headerBytes).toBe(14);
  });
});

describe('decideMerge (D7)', () => {
  const candidate = (over: Partial<MergeCandidate> = {}): MergeCandidate => ({
    hasGateway: true,
    hasIntake: false,
    bodySha256s: [A1],
    contentVariants: 0,
    mergedCopies: 0,
    status: 'active',
    ...over,
  });
  const limits = { maxContentVariants: 4, maxMergedCopies: 8, windowHours: 72 };
  const NOW = new Date('2026-11-20T00:00:00.000Z');

  it.each([
    [
      'intake into gateway, same body',
      candidate(),
      'journal_intake',
      A1,
      { action: 'merge', content: 'none' },
    ],
    [
      'intake into gateway, other body',
      candidate(),
      'journal_intake',
      B1,
      { action: 'merge', content: 'variant' },
    ],
    [
      'gateway into intake-only',
      candidate({ hasGateway: false, hasIntake: true }),
      'gateway',
      B1,
      { action: 'merge', content: 'variant' },
    ],
    [
      'intake into intake',
      candidate({ hasGateway: false, hasIntake: true }),
      'journal_intake',
      A1.toUpperCase(),
      { action: 'merge', content: 'none' },
    ],
    [
      'gateway into gateway',
      candidate(),
      'gateway',
      A1,
      { action: 'separate', reason: 'scope_gateway_gateway' },
    ],
    [
      'gateway into merged (has gateway)',
      candidate({ hasIntake: true }),
      'gateway',
      A1,
      { action: 'separate', reason: 'scope_gateway_gateway' },
    ],
    [
      'variant limit',
      candidate({ contentVariants: 4 }),
      'journal_intake',
      B1,
      { action: 'separate', reason: 'variant_limit' },
    ],
    [
      'variant limit does not stop a same-body merge',
      candidate({ contentVariants: 4 }),
      'journal_intake',
      A1,
      { action: 'merge', content: 'none' },
    ],
    [
      'merged limit',
      candidate({ mergedCopies: 8 }),
      'journal_intake',
      A1,
      { action: 'separate', reason: 'merged_limit' },
    ],
    [
      'inactive record',
      candidate({ status: 'expiry_review' }),
      'journal_intake',
      A1,
      { action: 'separate', reason: 'record_inactive' },
    ],
    [
      'outside the window',
      candidate({ keyCreatedAt: new Date(NOW.getTime() - 73 * 3_600_000) }),
      'journal_intake',
      A1,
      { action: 'separate', reason: 'outside_window' },
    ],
    [
      'inside the window',
      candidate({ keyCreatedAt: new Date(NOW.getTime() - 71 * 3_600_000) }),
      'journal_intake',
      A1,
      { action: 'merge', content: 'none' },
    ],
  ] as const)('%s', (_name, c, source, body, expected) => {
    expect(
      decideMerge({ candidate: c, incoming: { source, bodySha256: body }, limits, now: NOW }),
    ).toEqual(expected);
  });
});

describe('decideMerge copy consistency (D7 review fix: forged resends stay separate)', () => {
  const limits = { maxContentVariants: 4, maxMergedCopies: 8, windowHours: 72 };
  const NOW = new Date('2026-11-20T12:00:00.000Z');
  const at = (minutes: number) => new Date(NOW.getTime() + minutes * 60_000);
  const intakeRecord = (over: Partial<MergeCandidate> = {}): MergeCandidate => ({
    hasGateway: false,
    hasIntake: true,
    bodySha256s: [A1],
    contentVariants: 0,
    mergedCopies: 0,
    status: 'active',
    direction: 'outbound',
    receivedAt: at(0),
    ...over,
  });
  const decide = (
    c: MergeCandidate,
    incoming: Partial<Parameters<typeof decideMerge>[0]['incoming']>,
  ) =>
    decideMerge({
      candidate: c,
      incoming: { source: 'gateway', bodySha256: B1, ...incoming },
      limits,
      now: NOW,
    });

  it('an inbound resend of an organization user’s outbound or internal mail never merges', () => {
    for (const direction of ['outbound', 'internal'] as const) {
      expect(
        decide(intakeRecord({ direction }), { direction: 'inbound', receivedAt: at(10) }),
      ).toEqual({ action: 'separate', reason: 'direction_mismatch' });
    }
    // The journal copy of that resend does not merge into the user's record either.
    expect(
      decide(intakeRecord(), {
        source: 'journal_intake',
        direction: 'inbound',
        receivedAt: at(11),
      }),
    ).toEqual({ action: 'separate', reason: 'direction_mismatch' });
  });

  it('an outbound gateway copy merges into the outbound intake record in either order', () => {
    for (const minutes of [-30, 0, 30]) {
      expect(decide(intakeRecord(), { direction: 'outbound', receivedAt: at(minutes) })).toEqual({
        action: 'merge',
        content: 'variant',
      });
    }
  });

  it('an inbound gateway copy received after the intake copy is a resend (beyond the skew)', () => {
    const record = intakeRecord({ direction: 'inbound' });
    expect(decide(record, { direction: 'inbound', receivedAt: at(6) })).toEqual({
      action: 'separate',
      reason: 'order_mismatch',
    });
    expect(
      decide(record, {
        direction: 'inbound',
        receivedAt: new Date(at(0).getTime() + MERGE_ORDER_SKEW_MS),
      }),
    ).toEqual({ action: 'merge', content: 'variant' });
    // The legitimate order: the gateway delivered it before the provider journaled it.
    expect(decide(record, { direction: 'inbound', receivedAt: at(-3) })).toEqual({
      action: 'merge',
      content: 'variant',
    });
  });

  it('an inbound intake copy merges into an earlier gateway record, not into a later one', () => {
    const gatewayRecord = intakeRecord({
      hasGateway: true,
      hasIntake: false,
      direction: 'inbound',
    });
    const intake = { source: 'journal_intake' as const, direction: 'inbound' as const };
    expect(decide(gatewayRecord, { ...intake, receivedAt: at(2) })).toEqual({
      action: 'merge',
      content: 'variant',
    });
    expect(decide(gatewayRecord, { ...intake, receivedAt: at(-6) })).toEqual({
      action: 'separate',
      reason: 'order_mismatch',
    });
  });

  it('intake into intake, and a record holding both sources, have no order rule', () => {
    expect(
      decide(intakeRecord({ direction: 'inbound' }), {
        source: 'journal_intake',
        direction: 'inbound',
        receivedAt: at(60),
      }),
    ).toEqual({ action: 'merge', content: 'variant' });
    expect(
      decide(intakeRecord({ hasGateway: true, direction: 'inbound' }), {
        source: 'journal_intake',
        direction: 'inbound',
        receivedAt: at(-60),
      }),
    ).toEqual({ action: 'merge', content: 'variant' });
  });
});
