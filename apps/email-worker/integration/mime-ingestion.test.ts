import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { EventTypes, messageParsedV1, messageParseFailedV1 } from '@email-gateway/event-contracts';
import { PARSER_VERSION } from '@email-gateway/mime-parser';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PART_CONTENT_DISPOSITION } from '../src/mime-ingestion/s3-part-sink';
import { Fixtures, type MessageFixture, sha256, unreachableS3 } from './support/fixtures';
import { largeMessage, multipartMessage, nestedArchive, zipBomb } from './support/messages';

const CORPUS = resolve(__dirname, '../../../packages/mime-parser/test/fixtures');
const FINAL = ['parsed', 'parsed_with_defects', 'parse_limit_exceeded', 'parse_failed'];

let fx: Fixtures;
let org: bigint;

beforeAll(async () => {
  fx = new Fixtures();
  org = await fx.organization('main');
});

afterAll(async () => {
  await fx?.cleanup();
});

/** Every stored object's SHA-256 equals its row; keys are under the org and the message. */
async function expectObjectsMatchRows(message: MessageFixture) {
  const state = await fx.state(message);
  const parse = state.parses[0]!;
  const expected: { key: string; sha256: string }[] = [];
  if (parse.textBodyObjectKey)
    expected.push({ key: parse.textBodyObjectKey, sha256: parse.textBodySha256! });
  if (parse.htmlBodyObjectKey)
    expected.push({ key: parse.htmlBodyObjectKey, sha256: parse.htmlBodySha256! });
  for (const a of state.attachments)
    if (a.objectKey) expected.push({ key: a.objectKey, sha256: a.sha256 });
  for (const { key, sha256: digest } of expected) {
    expect(key.startsWith(`org/${message.organizationId.toString()}/part/`)).toBe(true);
    expect(key).toContain(`/${message.messageId.toString()}/`);
    expect(await fx.objectSha256(key)).toBe(digest);
  }
  expect(state.objects).toEqual(expected.map((e) => e.key).sort());
  return state;
}

describe('MIME ingestion against MySQL and MinIO (step 3.1 §9)', () => {
  it('parses a multipart message end to end: rows, objects, subject, event and outbox', async () => {
    const pdf = Buffer.from('%PDF-1.7\n% integration\n');
    const eml = multipartMessage({
      attachments: [
        { filename: 'Größe – Bericht.pdf', contentType: 'application/pdf', bytes: pdf },
        {
          filename: 'logo.png',
          contentType: 'image/png',
          bytes: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1]),
          disposition: 'inline',
        },
      ],
    });
    const message = await fx.message(org, { eml });
    const { service } = fx.ingestion();
    const event = fx.received(message);

    await expect(service.handle(event)).resolves.toBe('handled');

    const state = await expectObjectsMatchRows(message);
    expect(state.parses).toHaveLength(1);
    const parse = state.parses[0]!;
    expect(parse).toMatchObject({
      status: 'parsed',
      attempts: 1,
      parserVersion: PARSER_VERSION,
      eventId: event.eventId,
      organizationId: org,
      partCount: 6,
      attachmentCount: 2,
      bytesRead: BigInt(message.sizeBytes),
    });
    expect(parse.completedAt).not.toBeNull();
    expect(parse.textBodyCharset).toBe('utf-8');
    // The decoded subject replaced step 2.2's raw value; status and version are untouched.
    expect(state.message.subject).toBe('Überweisung ✓');
    expect(state.message.attachmentCount).toBe(2);
    expect(state.message.status).toBe('received');
    expect(state.message.version).toBe(0);
    expect(state.headers.map((h) => h.name)).toEqual([
      'Return-Path',
      'Authentication-Results',
      'From',
      'To',
      'Subject',
      'Date',
      'Message-ID',
    ]);
    const [report, logo] = state.attachments;
    expect(report).toMatchObject({
      filename: 'Größe – Bericht.pdf',
      disposition: 'attachment',
      declaredContentType: 'application/pdf',
      detectedContentType: 'application/pdf',
      sizeBytes: pdf.length,
      sha256: sha256(pdf),
      verdict: null,
      parentPartIndex: null,
    });
    expect(logo).toMatchObject({ disposition: 'inline', detectedContentType: 'image/png' });
    // Object headers: never rendered, no filename or header metadata (M11).
    const head = await fx.objectHead(report!.objectKey!);
    expect(head.contentType).toBe('application/octet-stream');
    expect(head.contentDisposition).toBe(PART_CONTENT_DISPOSITION);
    expect(head.metadata).toEqual({});
    expect((await fx.objectHead(parse.textBodyObjectKey!)).contentType).toBe(
      'text/plain; charset=utf-8',
    );

    expect(state.events).toHaveLength(1);
    expect(state.events[0]).toMatchObject({ eventType: 'parsed', sourceService: 'email-worker' });
    expect(state.outbox).toHaveLength(1);
    const outbox = state.outbox[0]!;
    expect(outbox).toMatchObject({
      eventType: EventTypes.MessageParsed,
      aggregateType: 'message',
      aggregateId: message.messageId.toString(),
      correlationId: event.correlationId,
      organizationId: org,
      publishedAt: null,
    });
    expect(state.events[0]!.eventId).toBe(outbox.eventId);
    const payload = messageParsedV1.parse(outbox.payload);
    expect(payload).toMatchObject({
      parseStatus: 'parsed',
      attachmentCount: 2,
      messageId: message.messageId.toString(),
    });
    expect(JSON.stringify(outbox.payload)).not.toContain('Bericht');
    // Ledger row of the consumer in the same transaction.
    expect(await fx.prisma.messageIdempotency.count({ where: { eventId: event.eventId } })).toBe(1);
  });

  it('parses the mime-parser corpus end to end with a final status and valid events', async () => {
    const { service } = fx.ingestion();
    const files = readdirSync(CORPUS)
      .filter((f) => f.endsWith('.eml'))
      .sort();
    expect(files.length).toBeGreaterThanOrEqual(30);
    const statuses: Record<string, string> = {};
    for (const file of files) {
      const eml = readFileSync(resolve(CORPUS, file));
      const message = await fx.message(org, { eml });
      await expect(service.handle(fx.received(message))).resolves.toBe('handled');
      const state = await expectObjectsMatchRows(message);
      const parse = state.parses[0]!;
      expect(FINAL).toContain(parse.status);
      statuses[file] = parse.status;
      expect(state.outbox).toHaveLength(1);
      expect(state.events).toHaveLength(1);
      const outbox = state.outbox[0]!;
      if (parse.status === 'parse_failed') messageParseFailedV1.parse(outbox.payload);
      else messageParsedV1.parse(outbox.payload);
      expect(parse.bytesRead).toBe(BigInt(eml.length));
    }
    // A few fixed expectations of the corpus (the rest is covered by the parser's unit tests).
    expect(statuses['alternative.eml']).toBe('parsed');
    expect(statuses['unterminated-multipart.eml']).toBe('parsed_with_defects');
    expect(statuses['part-flood.eml']).toBe('parse_limit_exceeded');
    expect(statuses['header-flood.eml']).toBe('parse_limit_exceeded');
  });

  it('flags a zip bomb and nested archives (M10) without decompressing them', async () => {
    const bomb = await zipBomb();
    const nested = await nestedArchive();
    const eml = multipartMessage({
      attachments: [
        { filename: 'bomb.zip', contentType: 'application/zip', bytes: bomb },
        { filename: 'nested.zip', contentType: 'application/zip', bytes: nested },
      ],
    });
    const message = await fx.message(org, { eml });
    const { service } = fx.ingestion();

    await service.handle(fx.received(message));

    const state = await expectObjectsMatchRows(message);
    const [bombRow, nestedRow] = state.attachments;
    expect(bombRow!.flags).toEqual(
      expect.arrayContaining(['archive', 'archive_compression_ratio']),
    );
    expect(bombRow!.archiveInfo).toMatchObject({ type: 'zip', inspected: true, entries: 1 });
    expect(
      (bombRow!.archiveInfo as { declaredUncompressedBytes: number }).declaredUncompressedBytes,
    ).toBe(200 * 1024 * 1024);
    expect(nestedRow!.flags).toEqual(expect.arrayContaining(['archive', 'archive_nested']));
    expect(nestedRow!.archiveInfo).toMatchObject({
      type: 'zip',
      inspected: true,
      entries: 3,
      nestedArchives: 2,
    });
    const payload = messageParsedV1.parse(state.outbox[0]!.payload);
    expect(payload.flaggedAttachmentCount).toBe(2);
    expect(payload.attachmentFlags).toEqual(
      expect.arrayContaining(['archive_compression_ratio', 'archive_nested']),
    );
  });

  it('streams a large email near MIME_MAX_MESSAGE_BYTES with bounded memory', async () => {
    const large = largeMessage();
    const message = await fx.streamedMessage(org, { chunks: large.chunks });
    const { service, config } = fx.ingestion();
    expect(message.sizeBytes).toBeGreaterThan(50 * 1024 * 1024);
    expect(message.sizeBytes).toBeLessThanOrEqual(config.MIME_MAX_MESSAGE_BYTES);

    // Live memory (after forced collections, --expose-gc) sampled while the stage runs.
    const gc = (globalThis as { gc?: () => void }).gc;
    expect(gc).toBeTypeOf('function');
    const live = () => {
      gc!();
      const usage = process.memoryUsage();
      return usage.heapUsed + usage.arrayBuffers;
    };
    const before = live();
    let peak = 0;
    const sampler = setInterval(() => {
      peak = Math.max(peak, live() - before);
    }, 25);
    try {
      await expect(service.handle(fx.received(message))).resolves.toBe('handled');
    } finally {
      clearInterval(sampler);
    }

    const state = await expectObjectsMatchRows(message);
    expect(state.parses[0]).toMatchObject({
      status: 'parsed',
      bytesRead: BigInt(message.sizeBytes),
    });
    expect(state.attachments.map((a) => a.sizeBytes)).toEqual(large.attachmentSizes);
    expect(state.attachments.map((a) => a.sha256)).toEqual(large.attachmentSha256);
    // The 53 MB message is never held whole: live growth stays far below its size (the upload
    // buffers are part size x (queue size + 1) = 15 MiB for the one open part).
    expect(peak).toBeLessThan(32 * 1024 * 1024);
  });

  it('records the size, attachment and body limits (pre-check and per part, M5)', async () => {
    const big = Buffer.alloc(2 * 1024 * 1024, 7);
    const eml = multipartMessage({
      text: 'x'.repeat(4096),
      attachments: [{ filename: 'big.bin', contentType: 'application/octet-stream', bytes: big }],
    });
    // Over the message limit: recorded from size_bytes, never downloaded.
    const tooLarge = await fx.message(org, { eml });
    await fx
      .ingestion({
        overrides: {
          MIME_MAX_MESSAGE_BYTES: String(eml.length - 1),
          MIME_MAX_ATTACHMENT_BYTES: '1024',
          MIME_MAX_BODY_BYTES: '1024',
        },
      })
      .service.handle(fx.received(tooLarge));
    let state = await fx.state(tooLarge);
    expect(state.parses[0]).toMatchObject({
      status: 'parse_limit_exceeded',
      limitsExceeded: ['message_size'],
      bytesRead: null,
    });
    expect(state.objects).toEqual([]);
    expect(state.headers).toEqual([]);

    // Over the attachment and body limits: rows with full size and hash, no objects.
    const perPart = await fx.message(org, { eml });
    await fx
      .ingestion({
        overrides: { MIME_MAX_ATTACHMENT_BYTES: String(1024 * 1024), MIME_MAX_BODY_BYTES: '1024' },
      })
      .service.handle(fx.received(perPart));
    state = await fx.state(perPart);
    expect(state.parses[0]!.status).toBe('parse_limit_exceeded');
    expect(state.parses[0]!.limitsExceeded).toEqual(
      expect.arrayContaining(['attachment_size', 'body_size']),
    );
    expect(state.parses[0]!.textBodyObjectKey).toBeNull();
    expect(state.parses[0]!.textBodySizeBytes).toBe(4096);
    expect(state.attachments[0]).toMatchObject({
      objectKey: null,
      sizeBytes: big.length,
      sha256: sha256(big),
    });
    expect(state.attachments[0]!.flags).toContain('not_stored_size_limit');
    // Only the HTML body was stored.
    expect(state.objects).toHaveLength(1);
    expect(state.objects[0]).toMatch(/\.html$/);
  });

  it('records eml_missing, eml_key_mismatch and integrity_mismatch as parse_failed', async () => {
    const { service } = fx.ingestion();
    const eml = multipartMessage();

    const missing = await fx.message(org, { eml, upload: false });
    await service.handle(fx.received(missing));
    const other = await fx.organization('keys');
    const mismatchedKey = await fx.message(org, {
      eml,
      emlObjectKey: `org/${other.toString()}/eml/it/foreign.eml`,
    });
    await service.handle(fx.received(mismatchedKey));
    const tampered = await fx.message(org, { eml, emlSha256: 'a'.repeat(64) });
    await service.handle(fx.received(tampered));

    for (const [message, reason] of [
      [missing, 'eml_missing'],
      [mismatchedKey, 'eml_key_mismatch'],
      [tampered, 'integrity_mismatch'],
    ] as const) {
      const state = await fx.state(message);
      expect(state.parses[0]).toMatchObject({ status: 'parse_failed', failureReason: reason });
      expect(state.headers).toEqual([]);
      expect(state.attachments).toEqual([]);
      expect(state.objects).toEqual([]);
      expect(state.message.subject).toBe('=?UTF-8?B?cmF3?=');
      expect(state.events[0]!.eventType).toBe('parse_failed');
      expect(messageParseFailedV1.parse(state.outbox[0]!.payload)).toMatchObject({
        reason,
        attempts: 1,
      });
    }
  });

  it('finalizes eml_key_mismatch for a stored key without any org/<id>/ prefix (null key)', async () => {
    const { service } = fx.ingestion();
    const message = await fx.message(org, { eml: multipartMessage(), upload: false });
    // The event carries the ingested key; the writer row (the only source of keys) does not.
    await fx.prisma.emailMessage.updateMany({
      where: { id: message.messageId, receivedAt: message.receivedAt, organizationId: org },
      data: { emlObjectKey: `eml/it/${message.messageId.toString()}.eml` },
    });

    await expect(service.handle(fx.received(message))).resolves.toBe('handled');
    const state = await fx.state(message);
    expect(state.parses[0]).toMatchObject({
      status: 'parse_failed',
      failureReason: 'eml_key_mismatch',
      attempts: 1,
    });
    expect(state.events[0]!.eventType).toBe('parse_failed');
    expect(state.outbox).toHaveLength(1);
    expect(messageParseFailedV1.parse(state.outbox[0]!.payload)).toMatchObject({
      reason: 'eml_key_mismatch',
      emlS3Key: null,
      attempts: 1,
    });
  });

  it('retries when S3 is unavailable without consuming the attempt, then parses', async () => {
    const message = await fx.message(org, { eml: multipartMessage() });
    const event = fx.received(message);
    const consumer = fx.consumer('outage');
    const outage = fx.ingestion({
      s3Client: unreachableS3(),
      consumer,
      overrides: { MIME_S3_TIMEOUT_MS: '3000' },
    });

    await expect(outage.service.handle(event)).rejects.toThrow();
    await expect(outage.service.handle(event)).rejects.toThrow();
    let state = await fx.state(message);
    expect(state.parses).toHaveLength(1);
    expect(state.parses[0]).toMatchObject({ status: 'parsing', attempts: 0 });
    expect(state.outbox).toEqual([]);
    expect(state.events).toEqual([]);
    expect(
      await fx.prisma.messageIdempotency.count({ where: { consumer, eventId: event.eventId } }),
    ).toBe(0);
    expect(await outage.registry.metrics()).toMatch(/mime_retries_total\{[^}]*class="s3"[^}]*\} 2/);

    await expect(fx.ingestion({ consumer }).service.handle(event)).resolves.toBe('handled');
    state = await fx.state(message);
    expect(state.parses[0]).toMatchObject({ status: 'parsed', attempts: 1 });
  });

  it('fails a message whose attempts reached MIME_MAX_ATTEMPTS (simulated crash loop)', async () => {
    const message = await fx.message(org, { eml: multipartMessage() });
    const { service, config } = fx.ingestion();
    await fx.prisma.emailMessageParse.create({
      data: {
        receivedAt: message.receivedAt,
        messageId: message.messageId,
        organizationId: org,
        status: 'parsing',
        attempts: config.MIME_MAX_ATTEMPTS,
        parserVersion: PARSER_VERSION,
        startedAt: new Date(),
      },
    });

    await service.handle(fx.received(message));

    const state = await fx.state(message);
    expect(state.parses[0]).toMatchObject({
      status: 'parse_failed',
      failureReason: 'max_attempts_exceeded',
      attempts: config.MIME_MAX_ATTEMPTS + 1,
    });
    expect(state.objects).toEqual([]);
    expect(messageParseFailedV1.parse(state.outbox[0]!.payload)).toMatchObject({
      reason: 'max_attempts_exceeded',
      attempts: config.MIME_MAX_ATTEMPTS + 1,
    });
  });

  it('ignores a cross-tenant envelope: no parse row, no objects, no events', async () => {
    const victim = await fx.message(org, { eml: multipartMessage() });
    const attacker = await fx.organization('attacker');
    const { service } = fx.ingestion();

    await expect(service.handle(fx.received(victim, { organizationId: attacker }))).resolves.toBe(
      'handled',
    );

    const state = await fx.state(victim);
    expect(state.parses).toEqual([]);
    expect(state.objects).toEqual([]);
    expect(state.events).toEqual([]);
    expect(state.outbox).toEqual([]);
    expect(state.message.subject).toBe('=?UTF-8?B?cmF3?=');
    expect(
      await fx.prisma.messageOutbox.count({
        where: {
          organizationId: attacker,
          eventType: { in: [EventTypes.MessageParsed, EventTypes.MessageParseFailed] },
        },
      }),
    ).toBe(0);
  });
});
