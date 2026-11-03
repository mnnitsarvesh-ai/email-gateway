import { Readable } from 'node:stream';
import { Prisma } from '@email-gateway/database';
import { messageParsedV1, messageParseFailedV1 } from '@email-gateway/event-contracts';
import {
  DEFAULT_MIME_LIMITS,
  type MimeParseResult,
  PARSER_VERSION,
} from '@email-gateway/mime-parser';
import { describe, expect, it } from 'vitest';
import { EML_MISSING } from './eml-source';
import {
  emlMessage,
  harness,
  metricValue,
  multipartEml,
  ORG,
  receivedEvent,
  silent,
} from './fakes.test-support';
import {
  integrityMismatch,
  MIME_CONSUMER,
  MimeIngestionService,
  outcomeOf,
} from './mime-ingestion.service';

const counter = (h: ReturnType<typeof harness>, name: string, label: string) =>
  metricValue(h.registry, name, label);

function setup(eml: string = multipartEml(), options: Parameters<typeof harness>[0] = {}) {
  const h = harness(options);
  const message = h.store.add(emlMessage(eml));
  h.source.put(message.emlObjectKey, eml);
  return { h, message };
}

describe('MimeIngestionService.handle (design M3)', () => {
  it('parses a message and finalizes rows, objects and one parsed event', async () => {
    const { h, message } = setup();
    const event = receivedEvent(message);

    await expect(h.service.handle(event)).resolves.toBe('handled');

    const row = h.store.parses.get(message.id);
    expect(row?.status).toBe('parsed');
    expect(row?.attempts).toBe(1);
    expect(h.store.ledger.has(`${MIME_CONSUMER}|${event.eventId}`)).toBe(true);
    expect(h.store.subjects.get(message.id)).toBe('Quarterly numbers');
    expect(h.store.headers.map((x) => x.name)).toEqual([
      'From',
      'To',
      'Subject',
      'Message-ID',
      'Date',
      'Authentication-Results',
    ]);
    expect(h.store.attachments).toHaveLength(1);
    expect(h.store.outbox).toHaveLength(1);
    const outbox = h.store.outbox[0]!;
    expect(outbox.eventType).toBe('mail.message.parsed.v1');
    expect(outbox.correlationId).toBe(event.correlationId);
    const payload = messageParsedV1.parse(outbox.payload);
    expect(payload).toMatchObject({
      messageId: message.id.toString(),
      parseStatus: 'parsed',
      parserVersion: PARSER_VERSION,
      attachmentCount: 1,
    });
    // Deterministic, organization-scoped keys (M11); every stored key is in the payload or rows.
    const keys = [...h.objects.objects.keys()].sort();
    expect(keys).toHaveLength(3);
    for (const key of keys) {
      expect(key).toMatch(
        new RegExp(
          `^org/${ORG.toString()}/part/2026/11/03/${message.id.toString()}/\\d+\\.(text|html|att)$`,
        ),
      );
    }
    expect(payload.textBody?.s3Key).toMatch(/\.text$/);
    expect(payload.htmlBody?.s3Key).toMatch(/\.html$/);
    expect(await counter(h, 'mime_parse_messages_total', 'status="parsed"')).toBe(1);
  });

  it('answers the same event twice with duplicate and no second effect (ledger pre-check)', async () => {
    const { h, message } = setup();
    const event = receivedEvent(message);
    await h.service.handle(event);
    const opened = h.source.opened;

    await expect(h.service.handle(event)).resolves.toBe('duplicate');
    expect(h.source.opened).toBe(opened);
    expect(h.store.outbox).toHaveLength(1);
    expect(h.store.events).toHaveLength(1);
  });

  it('never parses a message twice for a different event id (final parse row)', async () => {
    const { h, message } = setup();
    await h.service.handle(receivedEvent(message));
    const second = receivedEvent(message);

    await expect(h.service.handle(second)).resolves.toBe('duplicate');
    expect(h.source.opened).toBe(1);
    expect(h.store.outbox).toHaveLength(1);
    expect(h.store.headers).toHaveLength(6);
    // The second event is in the ledger, so a re-read stops at step 1.
    expect(h.store.ledger.has(`${MIME_CONSUMER}|${second.eventId}`)).toBe(true);
  });

  it('records only the ledger row for a message that does not exist', async () => {
    const h = harness();
    const ghost = emlMessage(multipartEml());
    const event = receivedEvent(ghost);

    await expect(h.service.handle(event)).resolves.toBe('handled');
    expect(h.store.parses.size).toBe(0);
    expect(h.store.outbox).toHaveLength(0);
    expect(h.store.ledger.has(`${MIME_CONSUMER}|${event.eventId}`)).toBe(true);
    expect(await counter(h, 'mime_parse_messages_total', 'status="message_missing"')).toBe(1);
  });

  it("ignores a cross-tenant envelope (organization not the writer row's)", async () => {
    const { h, message } = setup();
    const event = receivedEvent(message, { organizationId: '43' });

    await expect(h.service.handle(event)).resolves.toBe('handled');
    expect(h.store.parses.size).toBe(0);
    expect(h.source.opened).toBe(0);
    expect(h.store.outbox).toHaveLength(0);
    expect(h.objects.objects.size).toBe(0);
  });

  it('fails a message past MIME_MAX_ATTEMPTS without reading it (poison guard)', async () => {
    const { h, message } = setup(multipartEml(), { maxAttempts: 5 });
    h.store.parses.set(message.id, { status: 'parsing', attempts: 5 });

    await expect(h.service.handle(receivedEvent(message))).resolves.toBe('handled');
    expect(h.source.opened).toBe(0);
    const row = h.store.parses.get(message.id);
    expect(row).toMatchObject({ status: 'parse_failed', attempts: 6 });
    const payload = messageParseFailedV1.parse(h.store.outbox[0]!.payload);
    expect(payload).toMatchObject({ reason: 'max_attempts_exceeded', attempts: 6 });
    expect(h.store.events[0]!.eventType).toBe('parse_failed');
  });

  it('refuses an EML key outside the organization prefix (eml_key_mismatch)', async () => {
    const eml = multipartEml();
    const h = harness();
    const message = h.store.add(emlMessage(eml, { emlObjectKey: 'org/7/eml/2026/11/03/x.eml' }));
    h.source.put(message.emlObjectKey, eml);

    await h.service.handle(receivedEvent(message));
    expect(h.source.opened).toBe(0);
    expect(h.store.parses.get(message.id)?.status).toBe('parse_failed');
    expect(messageParseFailedV1.parse(h.store.outbox[0]!.payload).reason).toBe('eml_key_mismatch');
  });

  it('records message_size from size_bytes before downloading (pre-check)', async () => {
    const eml = multipartEml();
    const { h, message } = setup(eml, { limits: { maxMessageBytes: eml.length - 1 } });

    await h.service.handle(receivedEvent(message));
    expect(h.source.opened).toBe(0);
    const payload = messageParsedV1.parse(h.store.outbox[0]!.payload);
    expect(payload).toMatchObject({
      parseStatus: 'parse_limit_exceeded',
      limitsExceeded: ['message_size'],
      attachmentCount: 0,
      textBody: null,
    });
    expect(h.store.headers).toHaveLength(0);
  });

  it('records eml_missing when the stored EML does not exist', async () => {
    const h = harness();
    const message = h.store.add(emlMessage(multipartEml()));

    await h.service.handle(receivedEvent(message));
    expect(messageParseFailedV1.parse(h.store.outbox[0]!.payload).reason).toBe('eml_missing');
    expect(h.store.parses.get(message.id)?.status).toBe('parse_failed');
  });

  it("fails with integrity_mismatch on a different hash and deletes this attempt's objects", async () => {
    const eml = multipartEml();
    const h = harness();
    const message = h.store.add(emlMessage(eml, { emlSha256: 'a'.repeat(64) }));
    h.source.put(message.emlObjectKey, eml);

    await h.service.handle(receivedEvent(message));
    expect(messageParseFailedV1.parse(h.store.outbox[0]!.payload).reason).toBe(
      'integrity_mismatch',
    );
    expect(h.store.headers).toHaveLength(0);
    expect(h.store.attachments).toHaveLength(0);
    expect(h.store.subjects.has(message.id)).toBe(false);
    expect(h.objects.objects.size).toBe(0);
    expect(h.objects.deleted).toHaveLength(3);
  });

  it('fails with integrity_mismatch when the object is larger than size_bytes', async () => {
    const eml = multipartEml();
    const h = harness();
    const message = h.store.add(emlMessage(eml));
    h.source.put(message.emlObjectKey, `${eml}trailing bytes\r\n`);

    await h.service.handle(receivedEvent(message));
    expect(messageParseFailedV1.parse(h.store.outbox[0]!.payload).reason).toBe(
      'integrity_mismatch',
    );
  });

  it('gives the attempt back and rethrows on an S3 read failure, then parses on retry', async () => {
    const { h, message } = setup();
    const outage = Object.assign(new Error('connect ECONNREFUSED'), {
      name: 'TimeoutError',
      $metadata: {},
    });
    h.source.failOpen = outage;
    const event = receivedEvent(message);

    await expect(h.service.handle(event)).rejects.toBe(outage);
    expect(h.store.parses.get(message.id)).toMatchObject({ status: 'parsing', attempts: 0 });
    expect(h.store.outbox).toHaveLength(0);
    expect(h.store.ledger.size).toBe(0);
    expect(await counter(h, 'mime_retries_total', 'class="s3"')).toBe(1);

    await expect(h.service.handle(event)).resolves.toBe('handled');
    expect(h.store.parses.get(message.id)).toMatchObject({ status: 'parsed', attempts: 1 });
  });

  it('gives the attempt back and rethrows when a part upload fails (sink error)', async () => {
    const { h, message } = setup();
    const outage = Object.assign(new Error('upload failed'), {
      name: 'InternalError',
      $metadata: {},
    });
    h.objects.failWrite = outage;

    await expect(h.service.handle(receivedEvent(message))).rejects.toBe(outage);
    expect(h.store.parses.get(message.id)).toMatchObject({ status: 'parsing', attempts: 0 });
    expect(h.store.decrements).toBe(1);
  });

  it('gives the attempt back and rethrows when the finalize transaction fails (db)', async () => {
    const { h, message } = setup();
    const outage = new Prisma.PrismaClientKnownRequestError('Transaction API error', {
      code: 'P2028',
      clientVersion: 'test',
    });
    h.store.failFinalize = outage;

    await expect(h.service.handle(receivedEvent(message))).rejects.toBe(outage);
    expect(h.store.parses.get(message.id)).toMatchObject({ status: 'parsing', attempts: 0 });
    expect(await counter(h, 'mime_retries_total', 'class="db"')).toBe(1);
  });

  /** An S3 body that delivers the first 200 bytes and then stalls. */
  const stallingBody = (eml: string) =>
    new Readable({
      read() {
        if (!(this as Readable & { sent?: boolean }).sent) {
          (this as Readable & { sent?: boolean }).sent = true;
          this.push(Buffer.from(eml.slice(0, 200)));
        }
      },
    });

  it('retries (never parse_timeout) when the parse budget runs out on a stalled S3 body', async () => {
    const eml = multipartEml();
    const { h, message } = setup(eml, { limits: { parseTimeoutMs: 50 } });
    h.source.open = () => Promise.resolve(stallingBody(eml));

    await expect(h.service.handle(receivedEvent(message))).rejects.toMatchObject({
      name: 'S3Stalled',
    });
    expect(h.store.parses.get(message.id)).toMatchObject({ status: 'parsing', attempts: 0 });
    expect(h.store.outbox).toHaveLength(0);
    expect(h.store.ledger.size).toBe(0);
    expect(await counter(h, 'mime_retries_total', 'class="s3"')).toBe(1);
  });

  it('retries (never parse_timeout) when the download itself outlives the parse budget', async () => {
    const { h, message } = setup(multipartEml(), { limits: { parseTimeoutMs: 30 } });
    h.source.open = (_key: string, signal: AbortSignal) =>
      new Promise<never>((_resolve, reject) => {
        signal.addEventListener('abort', () =>
          reject(Object.assign(new Error('aborted'), { name: 'AbortError' })),
        );
      });

    await expect(h.service.handle(receivedEvent(message))).rejects.toMatchObject({
      name: 'S3Stalled',
    });
    expect(h.store.parses.get(message.id)).toMatchObject({ status: 'parsing', attempts: 0 });
    expect(h.store.outbox).toHaveLength(0);
  });

  it('retries when a part upload stalls past the parse budget', async () => {
    const h = harness();
    const message = h.store.add(emlMessage(multipartEml()));
    h.source.put(message.emlObjectKey, multipartEml());
    // Every part write waits on S3 forever.
    const stallingSink = (target: Parameters<typeof h.objects.sinkFor>[0]) => {
      const sink = h.objects.sinkFor(target);
      return {
        get writtenKeys() {
          return sink.writtenKeys;
        },
        deleteWritten: () => sink.deleteWritten(),
        open: async (part: Parameters<typeof sink.open>[0]) => ({
          ...(await sink.open(part)),
          write: () => new Promise<void>(() => undefined),
        }),
      };
    };
    const service = new MimeIngestionService({
      store: h.store,
      emlSource: h.source,
      sinkFor: stallingSink,
      metrics: h.metrics,
      logger: silent(),
      limits: { ...DEFAULT_MIME_LIMITS, parseTimeoutMs: 50 },
      maxAttempts: 5,
    });

    await expect(service.handle(receivedEvent(message))).rejects.toMatchObject({
      name: 'S3Stalled',
    });
    expect(h.store.parses.get(message.id)).toMatchObject({ status: 'parsing', attempts: 0 });
    expect(h.store.outbox).toHaveLength(0);
  });

  it('records parse_timeout when the budget runs out without a long S3 wait (slow parse)', async () => {
    const eml = multipartEml();
    // A clock that never advances: no S3 wait is ever long, so the timeout is the message's.
    const { h, message } = setup(eml, { limits: { parseTimeoutMs: 50 }, clock: () => 0 });
    h.source.open = () => Promise.resolve(stallingBody(eml));

    await expect(h.service.handle(receivedEvent(message))).resolves.toBe('handled');
    const payload = messageParsedV1.parse(h.store.outbox[0]!.payload);
    expect(payload.parseStatus).toBe('parse_limit_exceeded');
    expect(payload.limitsExceeded).toContain('parse_timeout');
    expect(h.store.decrements).toBe(0);
  });

  it('counts a deterministic finalize failure toward MIME_MAX_ATTEMPTS, then fails the message', async () => {
    const { h, message } = setup(multipartEml(), { maxAttempts: 3 });
    const event = receivedEvent(message);
    const tooLong = () =>
      new Prisma.PrismaClientKnownRequestError('Data too long for column', {
        code: 'P2000',
        clientVersion: 'test',
      });

    for (const attempt of [1, 2, 3]) {
      h.store.failFinalize = tooLong();
      await expect(h.service.handle(event)).rejects.toMatchObject({ code: 'P2000' });
      expect(h.store.parses.get(message.id)).toMatchObject({
        status: 'parsing',
        attempts: attempt,
      });
    }
    expect(h.store.decrements).toBe(0);
    expect(await counter(h, 'mime_retries_total', 'class="db"')).toBe(3);

    // Attempt 4 > MIME_MAX_ATTEMPTS: the poison guard ends it without reading the EML again.
    const opened = h.source.opened;
    await expect(h.service.handle(event)).resolves.toBe('handled');
    expect(h.source.opened).toBe(opened);
    expect(h.store.parses.get(message.id)).toMatchObject({ status: 'parse_failed', attempts: 4 });
    expect(messageParseFailedV1.parse(h.store.outbox[0]!.payload)).toMatchObject({
      reason: 'max_attempts_exceeded',
      attempts: 4,
    });
  });

  it('counts an unexpected exception (no outage) toward MIME_MAX_ATTEMPTS', async () => {
    const { h, message } = setup();
    h.store.failFinalize = new TypeError('unexpected');

    await expect(h.service.handle(receivedEvent(message))).rejects.toBeInstanceOf(TypeError);
    expect(h.store.parses.get(message.id)).toMatchObject({ status: 'parsing', attempts: 1 });
    expect(h.store.decrements).toBe(0);
  });

  it('finalizes eml_key_mismatch for a key without any org/<id>/ prefix (null key in the event)', async () => {
    for (const emlObjectKey of ['eml/x.eml', 'org/0/eml/x.eml', '/org/42/eml/x.eml', '']) {
      const h = harness();
      const message = h.store.add(emlMessage(multipartEml(), { emlObjectKey }));

      await expect(h.service.handle(receivedEvent(message))).resolves.toBe('handled');
      expect(h.source.opened).toBe(0);
      expect(h.store.parses.get(message.id)).toMatchObject({
        status: 'parse_failed',
        attempts: 1,
      });
      const payload = messageParseFailedV1.parse(h.store.outbox[0]!.payload);
      expect(payload).toMatchObject({ reason: 'eml_key_mismatch', emlS3Key: null });
      expect(h.store.decrements).toBe(0);
    }
  });

  it('treats a missing EML from the source as a content outcome, never an outage', async () => {
    const { h, message } = setup();
    h.source.open = () => Promise.resolve(EML_MISSING);
    await expect(h.service.handle(receivedEvent(message))).resolves.toBe('handled');
    expect(h.store.decrements).toBe(0);
  });
});

describe('outcome helpers', () => {
  const stats = {
    bytesRead: 10,
    sha256: 'b'.repeat(64),
    inputComplete: true,
    partCount: 1,
    maxDepth: 0,
    headerCount: 1,
    attachmentCount: 0,
    decodedBytes: 5,
    durationMs: 1,
  };
  const result = (overrides: Partial<MimeParseResult> = {}): MimeParseResult => ({
    status: 'parsed',
    limitsExceeded: [],
    defects: [],
    stats,
    subject: null,
    headers: [],
    textBody: null,
    htmlBody: null,
    attachments: [],
    structure: [],
    ...overrides,
  });

  it('maps a library parse_failed to parser_error, keeping what was extracted', () => {
    const r = result({
      status: 'parse_failed',
      failureReason: 'parser_error',
      defects: ['nul_bytes'],
    });
    expect(outcomeOf(r)).toMatchObject({
      status: 'parse_failed',
      failureReason: 'parser_error',
      defects: ['nul_bytes'],
      result: r,
    });
  });

  it('compares size and hash only for a complete read, and always flags extra bytes', () => {
    const message = emlMessage('x'.repeat(10), { emlSha256: 'b'.repeat(64) });
    expect(integrityMismatch(result(), message)).toBe(false);
    expect(
      integrityMismatch(result({ stats: { ...stats, sha256: 'c'.repeat(64) } }), message),
    ).toBe(true);
    expect(
      integrityMismatch(
        result({ stats: { ...stats, bytesRead: 4, inputComplete: false } }),
        message,
      ),
    ).toBe(false);
    expect(
      integrityMismatch(
        result({ stats: { ...stats, bytesRead: 11, inputComplete: false } }),
        message,
      ),
    ).toBe(true);
  });

  it('uses the default limits of design §5', () => {
    expect(DEFAULT_MIME_LIMITS.maxMessageBytes).toBe(53_477_376);
  });
});
