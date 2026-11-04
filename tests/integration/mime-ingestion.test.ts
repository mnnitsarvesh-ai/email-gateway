import { messageParsedV1, messageReceivedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { purgeDormantQueues } from './support/broker';
import { waitFor } from './support/compose';
import {
  encodedWord,
  malformedMessage,
  multipartMessage,
  parseState,
  rfc2231,
  STORED_HEADERS,
  waitForFinalParse,
} from './support/mime';
import { mimeStackGate } from './support/mime-stack';
import { sha256, SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply, swaks } from './support/smtp-tools';

/**
 * Post-queue MIME ingestion through the real Compose stack (docs/plan/steps/06-mime-ingestion.md
 * §9 stack test): smtp-tools → postfix:25 → LMTP 10050 → smtp-adapter ingestion (EML in MinIO,
 * `mail.message.received.v1` on the outbox) → email-worker MIME ingestion (outbox feed, streamed
 * GET of the EML, parts streamed to MinIO, one writer transaction with parse row, headers,
 * attachments, `parsed` event and `mail.message.parsed.v1`).
 */
const gate = await mimeStackGate();
const fx = new SmtpFixtures();
let org = 0n;
let domain: FixtureDomain;

const SENDER = 'mime-sender@example.org';
const SUBJECT = 'Überweisung ✓ – MIME stack';
/** RFC 2231 name with a Windows path component (sanitized to its last component, M9). */
const RAW_FILENAME = 'C:\\Users\\Finanz\\Größe – Bericht.pdf';
const SANITIZED_FILENAME = 'Größe – Bericht.pdf';
const ESCAPED_FILENAME = 'C:\\u{005C}Users\\u{005C}Finanz\\u{005C}Größe – Bericht.pdf';
const PDF = Buffer.from('%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n', 'latin1');
const TEXT_QP = 'Hello =E2=9C=93 MIME stack.';
const HTML = '<p>Hello MIME stack.</p>';

function waitForStored(queueId: string) {
  return waitFor(
    `email_messages row for queue id ${queueId}`,
    () =>
      fx.prisma.emailMessage
        .findFirst({ where: { organizationId: org, mtaQueueId: queueId } })
        .then((row) => row ?? undefined),
    { timeoutMs: 60_000 },
  );
}

beforeAll(async () => {
  assertStackReady(gate);
  org = await fx.organization('mime');
  domain = await fx.domain(org, 'mime');
}, 60_000);

afterAll(async () => {
  if (gate.skip) return;
  await fx.cleanup();
  await purgeDormantQueues();
}, 120_000);

describe.skipIf(gate.skip)('MIME ingestion stack (step 3.1 §9)', { timeout: 180_000 }, () => {
  it('parses an inbound multipart message: headers, bodies, attachment, subject, event, outbox', async () => {
    const rcpt = `alice@${domain.name}`;
    const { text, messageId } = multipartMessage({
      from: SENDER,
      to: [rcpt],
      subjectHeader: encodedWord(SUBJECT),
      textQp: TEXT_QP,
      html: HTML,
      attachment: {
        contentType: 'application/pdf',
        dispositionParam: rfc2231('filename', RAW_FILENAME),
        bytes: PDF,
      },
    });
    const sent = await swaks({ server: 'postfix', port: 25, from: SENDER, to: [rcpt], data: text });
    expect(reply(sent, 'DATA-END').text).toMatch(/^250 2\.0\.0 Ok: queued as /);

    // Step 2.2: the message row, then step 3.1: its final parse row.
    const stored = await waitForStored(sent.queueId!);
    const parse = await waitForFinalParse(fx, stored);
    expect(parse).toMatchObject({
      organizationId: org,
      status: 'parsed',
      attempts: 1,
      failureReason: null,
      attachmentCount: 1,
      bytesRead: BigInt(stored.sizeBytes),
      textBodyCharset: 'utf-8',
      htmlBodyCharset: 'utf-8',
    });
    expect(parse.limitsExceeded ?? []).toEqual([]);
    expect(parse.defects ?? []).toEqual([]);
    // The parse started from the received event ingestion committed for this message.
    const received = await fx.prisma.messageOutbox.findFirstOrThrow({
      where: {
        organizationId: org,
        aggregateId: stored.id.toString(),
        eventType: 'mail.message.received.v1',
      },
    });
    expect(messageReceivedV1.parse(received.payload).messageId).toBe(stored.id.toString());
    expect(parse.eventId).toBe(received.eventId);

    const state = await parseState(fx, stored);

    // email_messages: decoded subject and the attachment count; ingestion's fields unchanged.
    expect(state.message.subject).toBe(SUBJECT);
    expect(state.message.attachmentCount).toBe(1);
    expect(state.message.internetMessageId).toBe(messageId);
    expect(state.message.emlSha256).toBe(stored.emlSha256);
    expect(state.message.headerFrom).toBe(SENDER);

    // email_headers: allow-list only, in order of appearance, decoded values.
    const names = state.headers.map((h) => h.name);
    for (const name of names) expect(STORED_HEADERS).toContain(name);
    expect(names).not.toContain('Received');
    expect(names).not.toContain('Content-Type');
    expect(state.headers.map((h) => h.seq)).toEqual(names.map((_, i) => i));
    const header = (name: string) => state.headers.filter((h) => h.name === name);
    expect(header('Subject').map((h) => h.value)).toEqual([SUBJECT]);
    expect(header('From').map((h) => h.value)).toEqual([SENDER]);
    expect(header('To').map((h) => h.value)).toEqual([rcpt]);
    expect(header('Message-ID').map((h) => h.value)).toEqual([messageId]);
    expect(header('Date')).toHaveLength(1);
    expect(names.indexOf('From')).toBeLessThan(names.indexOf('Subject'));
    for (const h of state.headers) expect(h.organizationId).toBe(org);

    // Bodies: decoded UTF-8 objects under the org's part prefix; SHA-256 of the object = row.
    const partPrefix = new RegExp(
      `^org/${org.toString()}/part/\\d{4}/\\d{2}/\\d{2}/${stored.id.toString()}/\\d+\\.`,
    );
    expect(parse.textBodyObjectKey).toMatch(new RegExp(`${partPrefix.source}text$`));
    expect(parse.htmlBodyObjectKey).toMatch(new RegExp(`${partPrefix.source}html$`));
    const textObject = await fx.object(parse.textBodyObjectKey!);
    const htmlObject = await fx.object(parse.htmlBodyObjectKey!);
    expect(sha256(textObject)).toBe(parse.textBodySha256);
    expect(textObject.length).toBe(parse.textBodySizeBytes);
    expect(textObject.toString('utf8')).toMatch(/^Hello ✓ MIME stack\.(\r\n)?$/);
    expect(sha256(htmlObject)).toBe(parse.htmlBodySha256);
    expect(htmlObject.length).toBe(parse.htmlBodySizeBytes);
    expect(htmlObject.toString('utf8')).toMatch(/^<p>Hello MIME stack\.<\/p>(\r\n)?$/);

    // email_attachments: sanitized and escaped names, path flag, sniffed type, object hash.
    expect(state.attachments).toHaveLength(1);
    const attachment = state.attachments[0]!;
    expect(attachment).toMatchObject({
      organizationId: org,
      filename: SANITIZED_FILENAME,
      originalFilename: ESCAPED_FILENAME,
      disposition: 'attachment',
      declaredContentType: 'application/pdf',
      detectedContentType: 'application/pdf',
      sizeBytes: PDF.length,
      sha256: sha256(PDF),
      parentPartIndex: null,
      verdict: null,
    });
    expect(attachment.flags).toEqual(expect.arrayContaining(['filename_path_stripped']));
    expect(attachment.objectKey).toMatch(new RegExp(`${partPrefix.source}att$`));
    const attachmentObject = await fx.object(attachment.objectKey!);
    expect(sha256(attachmentObject)).toBe(attachment.sha256);
    expect(attachmentObject.equals(PDF)).toBe(true);
    // Filenames are never part of a key.
    expect(attachment.objectKey).not.toContain('Bericht');

    // Exactly the three part objects plus the EML under the org prefix.
    const keys = (await fx.objectKeys(org)).sort();
    expect(keys).toEqual(
      [
        stored.emlObjectKey,
        parse.textBodyObjectKey!,
        parse.htmlBodyObjectKey!,
        attachment.objectKey!,
      ].sort(),
    );

    // email_events: one `parsed` row by the email-worker, linked to the outbox event.
    const parsedEvents = state.events.filter((e) => e.sourceService === 'email-worker');
    expect(parsedEvents.map((e) => e.eventType)).toEqual(['parsed']);

    // message_outbox: exactly one mail.message.parsed.v1, ids and codes only.
    expect(state.outbox).toHaveLength(1);
    const outbox = state.outbox[0]!;
    expect(outbox).toMatchObject({
      eventType: 'mail.message.parsed.v1',
      aggregateType: 'message',
      aggregateId: stored.id.toString(),
      correlationId: received.correlationId,
    });
    // Step 3.2: the event-relay publishes the parse event (confirmed) and marks the row.
    await waitFor(
      'the mail.message.parsed.v1 row published by the event-relay',
      async () =>
        (await fx.prisma.messageOutbox.findFirst({
          where: { id: outbox.id, publishedAt: { not: null } },
        })) !== null,
      { timeoutMs: 30_000 },
    );
    expect(parsedEvents[0]!.eventId).toBe(outbox.eventId);
    const payload = messageParsedV1.parse(outbox.payload);
    expect(payload).toMatchObject({
      messageId: stored.id.toString(),
      direction: 'inbound',
      emlS3Key: stored.emlObjectKey,
      parseStatus: 'parsed',
      limitsExceeded: [],
      defects: [],
      textBody: {
        s3Key: parse.textBodyObjectKey,
        sha256: parse.textBodySha256,
        sizeBytes: parse.textBodySizeBytes,
      },
      htmlBody: {
        s3Key: parse.htmlBodyObjectKey,
        sha256: parse.htmlBodySha256,
        sizeBytes: parse.htmlBodySizeBytes,
      },
      attachmentCount: 1,
    });
    expect(payload.attachmentFlags).toContain('filename_path_stripped');
    const json = JSON.stringify(outbox.payload);
    for (const forbidden of [
      SENDER,
      rcpt,
      domain.name,
      'Überweisung',
      encodedWord(SUBJECT),
      'Bericht',
      'Größe',
      'Finanz',
    ]) {
      expect(json).not.toContain(forbidden);
    }
    // The consumer's ledger row for the received event.
    expect(
      await fx.prisma.messageIdempotency.count({
        where: { consumer: 'email-worker.mime-parser', eventId: received.eventId },
      }),
    ).toBe(1);
  });

  it('records a malformed message (no closing boundary, bad base64) as parsed_with_defects', async () => {
    const rcpt = `bob@${domain.name}`;
    const { text } = malformedMessage({ from: SENDER, to: [rcpt], subject: 'Malformed MIME' });
    const sent = await swaks({ server: 'postfix', port: 25, from: SENDER, to: [rcpt], data: text });
    expect(reply(sent, 'DATA-END').text).toMatch(/^250 2\.0\.0 Ok: queued as /);

    const stored = await waitForStored(sent.queueId!);
    const parse = await waitForFinalParse(fx, stored);
    expect(parse.status).toBe('parsed_with_defects');
    expect(parse.failureReason).toBeNull();
    expect(parse.limitsExceeded ?? []).toEqual([]);
    expect(parse.defects).toEqual(
      expect.arrayContaining(['missing_closing_boundary', 'invalid_base64']),
    );

    const state = await parseState(fx, stored);
    expect(state.message.subject).toBe('Malformed MIME');
    // Best effort: the text body and the broken attachment are still recorded.
    expect(parse.textBodyObjectKey).not.toBeNull();
    expect(sha256(await fx.object(parse.textBodyObjectKey!))).toBe(parse.textBodySha256);
    expect(state.attachments).toHaveLength(1);
    const attachment = state.attachments[0]!;
    expect(attachment.filename).toBe('broken.bin');
    expect(sha256(await fx.object(attachment.objectKey!))).toBe(attachment.sha256);

    expect(
      state.events.filter((e) => e.sourceService === 'email-worker').map((e) => e.eventType),
    ).toEqual(['parsed']);
    expect(state.outbox).toHaveLength(1);
    const payload = messageParsedV1.parse(state.outbox[0]!.payload);
    expect(payload.parseStatus).toBe('parsed_with_defects');
    expect(payload.defects).toEqual(
      expect.arrayContaining(['missing_closing_boundary', 'invalid_base64']),
    );
  });
});
