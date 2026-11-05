import type { PrismaClient } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import {
  InconsistentAttachmentReadError,
  limitMayHideAttachments,
  PrismaAttachmentStore,
} from './attachment-store';

const MESSAGE = 55n;
const ORG = 7n;
const AT = new Date('2026-11-05T10:00:00.123Z');
const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);

const parseRow = (over: Record<string, unknown> = {}) => ({
  messageId: MESSAGE,
  receivedAt: new Date(AT),
  organizationId: ORG,
  status: 'parsed',
  limitsExceeded: [],
  attachmentCount: 2,
  ...over,
});

const attachmentRow = (partIndex: number, over: Record<string, unknown> = {}) => ({
  id: BigInt(100 + partIndex),
  messageId: MESSAGE,
  receivedAt: new Date(AT),
  organizationId: ORG,
  partIndex,
  filename: 'a.pdf',
  declaredContentType: 'application/pdf',
  sizeBytes: 10,
  sha256: SHA_A,
  objectKey: `org/7/part/2026/11/05/55/${String(partIndex)}.att`,
  flags: '[]',
  ...over,
});

/** The three reads of the store, each returning what the test sets (a wrong read included). */
function store(results: { parse?: unknown; attachments?: unknown[]; hashes?: unknown[] }) {
  const calls: Array<{ model: string; args: unknown }> = [];
  const prisma = {
    emailMessageParse: {
      findFirst: (args: unknown) => {
        calls.push({ model: 'parse', args });
        return Promise.resolve(results.parse ?? null);
      },
    },
    emailAttachment: {
      findMany: (args: unknown) => {
        calls.push({ model: 'attachments', args });
        return Promise.resolve(results.attachments ?? []);
      },
    },
    malwareSignature: {
      findMany: (args: unknown) => {
        calls.push({ model: 'hashes', args });
        return Promise.resolve(results.hashes ?? []);
      },
    },
  } as unknown as PrismaClient;
  return { store: new PrismaAttachmentStore(prisma), calls };
}

const inconsistent = (read: string, check: string): unknown =>
  expect.objectContaining({ name: 'InconsistentAttachmentReadError', read, check }) as unknown;

describe('PrismaAttachmentStore echo checks (step 4.2 §6, wrong reads after a writer stall)', () => {
  it('only body_size never hides an attachment (A6 E1)', () => {
    expect(limitMayHideAttachments('body_size')).toBe(false);
    for (const limit of [
      'message_size',
      'nesting_depth',
      'part_count',
      'header_count',
      'header_line_length',
      'header_block_size',
      'attachment_count',
      'attachment_size',
      'decoded_ratio',
      'total_decoded_size',
      'parse_timeout',
      'unknown_future_limit',
    ]) {
      expect(limitMayHideAttachments(limit), limit).toBe(true);
    }
  });

  it('returns the parse row with its attachment count when the identity echoes', async () => {
    const { store: s, calls } = store({
      parse: parseRow({ limitsExceeded: '["body_size"]', attachmentCount: 3 }),
    });
    expect(await s.loadParse(MESSAGE, AT, ORG)).toEqual({
      status: 'parsed',
      limitsExceeded: ['body_size'],
      attachmentCount: 3,
    });
    expect(calls[0]!.args).toMatchObject({
      where: { messageId: MESSAGE, receivedAt: AT, organizationId: ORG },
      select: { messageId: true, receivedAt: true, organizationId: true, attachmentCount: true },
    });
    expect(await store({}).store.loadParse(MESSAGE, AT, ORG)).toBeNull();
  });

  it.each([
    ['message', { messageId: 56n }],
    ['organization', { organizationId: 8n }],
    ['received_at', { receivedAt: new Date(AT.getTime() + 1) }],
    ['a row of another shape', { receivedAt: '2026-11-05' }],
  ])('refuses a parse row of another %s', async (_name, over) => {
    const { store: s } = store({ parse: parseRow(over) });
    await expect(s.loadParse(MESSAGE, AT, ORG)).rejects.toEqual(
      inconsistent('parse', 'identity echo'),
    );
  });

  it('returns the attachment rows without the echo columns', async () => {
    const { store: s } = store({ attachments: [attachmentRow(1), attachmentRow(3)] });
    const rows = await s.loadAttachments(MESSAGE, AT, ORG, 101);
    expect(rows.map((r) => r.partIndex)).toEqual([1, 3]);
    expect(rows[0]).toEqual({
      id: 101n,
      partIndex: 1,
      filename: 'a.pdf',
      declaredContentType: 'application/pdf',
      sizeBytes: 10,
      sha256: SHA_A,
      objectKey: 'org/7/part/2026/11/05/55/1.att',
      flags: [],
    });
  });

  it('refuses attachment rows of another message, organization or time, or out of order', async () => {
    for (const over of [
      { messageId: 56n },
      { organizationId: 8n },
      { receivedAt: new Date(AT.getTime() - 1) },
    ]) {
      const { store: s } = store({ attachments: [attachmentRow(1), attachmentRow(2, over)] });
      await expect(s.loadAttachments(MESSAGE, AT, ORG, 101)).rejects.toEqual(
        inconsistent('attachments', 'identity echo'),
      );
    }
    const { store: s } = store({ attachments: [attachmentRow(2), attachmentRow(2)] });
    await expect(s.loadAttachments(MESSAGE, AT, ORG, 101)).rejects.toEqual(
      inconsistent('attachments', 'part order'),
    );
  });

  it('refuses a known-hash result with a hash that was not requested', async () => {
    const ok = store({ hashes: [{ sha256: SHA_A, severity: 'high', family: 'Test' }] });
    expect(await ok.store.knownHashes([SHA_A, SHA_B], new Date())).toEqual(
      new Map([[SHA_A, { severity: 'high', family: 'Test' }]]),
    );
    const wrong = store({ hashes: [{ sha256: 'c'.repeat(64), severity: 'high', family: null }] });
    await expect(wrong.store.knownHashes([SHA_A], new Date())).rejects.toBeInstanceOf(
      InconsistentAttachmentReadError,
    );
  });
});
