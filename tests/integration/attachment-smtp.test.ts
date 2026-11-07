import { randomInt } from 'node:crypto';
import {
  EICAR_CLAMAV_SIGNATURE,
  EICAR_SHA256,
  eicar,
  encryptedZip,
  nestedZip,
  pdfLike,
} from '@email-gateway/attachment-corpus';
import { attachmentSandboxRequestedV1, messageScannedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, type ApiSession } from './support/api-client';
import {
  attachmentMessage,
  deliveryWorkerCounter,
  type MessageAttachment,
} from './support/attachment-stack';
import { eventually, ManagementApi, purgeDormantQueues } from './support/broker';
import { waitFor } from './support/compose';
import { waitForAllDeliveries, waitForMessage } from './support/deliveries';
import { stack } from './support/env';
import {
  DELIVERED_PATH,
  expectConsistentHistory,
  lifecycleOf,
  pathOf,
  waitForLifecycle,
} from './support/lifecycle';
import { clearSinkDomain, sinkFiles, SINK_SERVICES } from './support/mail-sink';
import { record, sleep } from './support/messaging-stack';
import { MAIL_SINK_HOST, organizationRef } from './support/routing';
import {
  attachmentResultsOf,
  engineResultsOf,
  messagePublicId,
  REQUIRED_ENGINES,
  sandboxSubmissionsOf,
  scannedEventsOf,
  scanStackGate,
  sendToMx,
  waitForRoundComplete,
} from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply } from './support/smtp-tools';

/**
 * The step 4.2 attachment engine end to end through the inbound Postfix (docs/plan/steps/
 * 10-attachment-scanning.md §9 "Stack", A1, A3, A6, A11, A15, A16): smtp-tools → postfix:25 →
 * smtp-adapter (EML in MinIO) → email-worker MIME role (part objects + `email_attachments`) →
 * `parsed.v1` → `scan.spam` (Rspamd) and `scan.attachment` (the attachment engine: part object
 * from MinIO, clamd INSTREAM ∥ the inspector child, known hashes, mapper) → round completion →
 * dev pass-through → postfix-outbound → mail-sink.
 *
 * - EICAR as a plain attachment: round `completed` with verdict `malicious`, attachment final
 *   `malicious` with `malware.clamav` (ClamAV `Eicar-Test-Signature`); the dev pass-through does
 *   NOT approve it (A15: `delivery_approvals_skipped_total{reason="malicious_verdict"}` +1, the
 *   message stays `scanned`, no approval, no delivery, nothing in any sink); the scans read API
 *   (replica) shows the per-attachment row.
 * - A clean PDF-like attachment (unique bytes per run, so never a cache hit of another run): clean
 *   attachment row (`clean.no_findings`, ClamAV OK), approved and delivered.
 * - No attachments: attachment final `skipped` with `attachment.none` (rule A0), delivered.
 * - EICAR inside a zip inside a zip: `malicious`.
 * - An encrypted zip: `suspicious` with `archive.encrypted`, one `sandbox_submissions` row and
 *   one `mail.attachment.sandbox_requested.v1`, which the relay publishes to the dormant
 *   `scan.sandbox` (peeked, then purged); suspicious is approved and delivered.
 *
 * Every test file is generated at test time by `@email-gateway/attachment-corpus` (EICAR is
 * assembled from fragments; nothing binary is committed).
 */
const gate = await scanStackGate();
const fx = new SmtpFixtures();
let org = 0n;
let domain: FixtureDomain;
let session: ApiSession | undefined;
const mgmt = new ManagementApi();
const vhost = stack.rabbitmqVhost();

beforeAll(async () => {
  assertStackReady(gate);
  org = await fx.organization('att-smtp');
  domain = await fx.domain(org, 'att-smtp');
  await fx.destinations(domain, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  session = await apiSession(fx.prisma, await organizationRef(fx, org), 'security_analyst');
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  await session?.remove();
  if (domain) await clearSinkDomain(domain.name, 'all').catch(() => undefined);
  await fx.cleanup();
  await purgeDormantQueues();
}, 120_000);

const codes = (value: unknown): string[] => (Array.isArray(value) ? (value as string[]) : []);

async function send(local: string, subject: string, attachments: readonly MessageAttachment[]) {
  const rcpt = `${local}@${domain.name}`;
  const built = attachmentMessage({
    from: 'alice@clean.scan.test',
    to: [rcpt],
    subject,
    attachments,
  });
  const started = Date.now();
  const sent = await sendToMx({
    from: 'alice@clean.scan.test',
    to: [rcpt],
    helo: 'mx.clean.scan.test',
    data: built.text,
  });
  expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
  const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
  const round = await waitForRoundComplete(fx.prisma, message, 0, 180_000);
  const scannedAfterMs = Date.now() - started;
  const finals = (await engineResultsOf(fx.prisma, message)).filter((r) => r.isFinal);
  const attachmentFinal = finals.find((r) => r.engine === 'attachment');
  return { rcpt, message, round, finals, attachmentFinal, scannedAfterMs, started };
}

/** The scans read API (replica) once round 0 is completed; the attachment engine entry. */
async function attachmentEngineView(publicId: string) {
  const page = await waitFor(
    `GET /messages/${publicId}/scans with a completed round`,
    async () => {
      const res = await session!.get(`/messages/${publicId}/scans`);
      if (res.status !== 200) return undefined;
      const body = res.body as {
        data: {
          round: number;
          status: string;
          verdict: string | null;
          requiredEngines: string[];
          engines: {
            engine: string;
            final: boolean;
            outcome: string | null;
            reasonCodes: string[];
            attachments?: Record<string, unknown>[];
          }[];
        }[];
      };
      return body.data.length === 1 && body.data[0]!.status !== 'running' ? body : undefined;
    },
    { timeoutMs: 30_000, intervalMs: 500 },
  );
  const round = page.data[0]!;
  return { round, engine: round.engines.find((e) => e.engine === 'attachment')! };
}

async function expectNotInAnySink(rcpt: string): Promise<void> {
  for (const service of SINK_SERVICES) expect(await sinkFiles(rcpt, service), service).toEqual([]);
}

describe.skipIf(gate.skip)('attachment stack: engine through Postfix', { timeout: 300_000 }, () => {
  it('EICAR attachment: malicious (malware.clamav), held in scanned by the dev pass-through, never delivered', async () => {
    const skippedBefore = await deliveryWorkerCounter('delivery_approvals_skipped_total', {
      reason: 'malicious_verdict',
    });
    const { rcpt, message, round, finals, attachmentFinal, scannedAfterMs } = await send(
      'eicar',
      'Attachment stack: EICAR',
      [{ filename: 'readme.txt', contentType: 'text/plain', bytes: eicar() }],
    );
    expect(round).toMatchObject({
      status: 'completed',
      scanVerdict: 'malicious',
      requiredEngines: [...REQUIRED_ENGINES],
    });
    expect(codes(round.reasonCodes)).toContain('malware.clamav');
    expect(finals.map((f) => f.engine).sort()).toEqual(['attachment', 'bec', 'rspamd', 'url']);
    expect(attachmentFinal).toMatchObject({ outcome: 'malicious', errorCode: null });
    expect(codes(attachmentFinal!.reasonCodes)).toContain('malware.clamav');
    expect(attachmentFinal!.engineVersion).toMatch(/^clamav\/1\.\d+\.\d+\/\d+;yara-x\//);

    // One per-attachment row: the EICAR file, ClamAV's signature, no filename stored.
    const [row, ...more] = await attachmentResultsOf(fx.prisma, message);
    expect(more).toEqual([]);
    expect(row).toMatchObject({
      organizationId: org,
      scanId: round.id,
      sha256: EICAR_SHA256,
      sizeBytes: 68,
      verdict: 'malicious',
      clamavSignature: expect.stringContaining(EICAR_CLAMAV_SIGNATURE),
    });
    expect(codes(row!.reasonCodes)).toContain('malware.clamav');
    expect(
      JSON.stringify(row, (_k, v: unknown) => (typeof v === 'bigint' ? `${v}` : v)),
    ).not.toContain('readme.txt');
    expect(await sandboxSubmissionsOf(fx.prisma, message)).toEqual([]);
    const [scanned] = await scannedEventsOf(fx.prisma, org, message);
    expect(messageScannedV1.parse(scanned!.payload)).toMatchObject({
      outcome: 'scanned',
      verdict: 'malicious',
    });

    // A15: the pass-through handles the scanned event but never approves malicious.
    await waitFor(
      'the dev pass-through to skip the malicious message',
      async () => {
        const after = await deliveryWorkerCounter('delivery_approvals_skipped_total', {
          reason: 'malicious_verdict',
        });
        return after !== undefined && skippedBefore !== undefined && after >= skippedBefore + 1;
      },
      { timeoutMs: 60_000, intervalMs: 1_000 },
    );
    await sleep(10_000);
    const skippedAfter = await deliveryWorkerCounter('delivery_approvals_skipped_total', {
      reason: 'malicious_verdict',
    });
    expect(skippedAfter).toBe(skippedBefore! + 1);
    expect(await lifecycleOf(fx.prisma, message)).toMatchObject({
      status: 'scanned',
      statusReason: 'scan_complete',
      lifecycleRound: 0,
    });
    expect((await pathOf(fx.prisma, message)).at(-1)).toEqual([
      'scanning',
      'scanned',
      'scan_complete',
    ]);
    const approvals = await fx.prisma.messageOutbox.findMany({
      where: { organizationId: org, eventType: 'mail.delivery.approved.v1' },
      select: { payload: true },
    });
    expect(
      approvals.filter(
        (a) => (a.payload as { messageId?: string }).messageId === message.id.toString(),
      ),
    ).toEqual([]);
    expect(
      await fx.prisma.emailDelivery.count({
        where: { organizationId: org, messageId: message.id },
      }),
    ).toBe(0);
    await expectNotInAnySink(rcpt);
    await expectConsistentHistory(fx.prisma, message);

    // The read API (replica) shows the attachment with its sanitized filename and ClamAV result.
    const view = await attachmentEngineView(await messagePublicId(fx.prisma, message));
    expect(view.round).toMatchObject({ verdict: 'malicious' });
    expect(view.engine).toMatchObject({ final: true, outcome: 'malicious' });
    expect(view.engine.attachments).toHaveLength(1);
    expect(view.engine.attachments![0]).toMatchObject({
      partIndex: row!.partIndex,
      sha256: EICAR_SHA256,
      sizeBytes: 68,
      verdict: 'malicious',
      filename: 'readme.txt',
      clamav: { signature: expect.stringContaining(EICAR_CLAMAV_SIGNATURE) },
      sandbox: null,
    });
    expect(codes(view.engine.attachments![0]!.reasonCodes)).toContain('malware.clamav');
    record('attachment-smtp', {
      eicar_verdict: round.scanVerdict,
      eicar_signature: row!.clamavSignature,
      eicar_cache: row!.cacheResult,
      eicar_engine_ms: attachmentFinal!.durationMs,
      eicar_smtp_to_scanned_ms: scannedAfterMs,
      malicious_skips_delta: skippedAfter! - skippedBefore!,
    });
  });

  it('a clean attachment is scanned clean and delivered', async () => {
    const bytes = pdfLike(48 * 1024, randomInt(1, 2 ** 31));
    const { rcpt, message, round, attachmentFinal, scannedAfterMs, started } = await send(
      'clean',
      'Attachment stack: clean PDF',
      [{ filename: 'statement.pdf', contentType: 'application/pdf', bytes }],
    );
    expect(round).toMatchObject({ status: 'completed', requiredEngines: [...REQUIRED_ENGINES] });
    expect(round.scanVerdict).not.toBe('malicious');
    expect(attachmentFinal).toMatchObject({ outcome: 'clean', errorCode: null });
    const [row, ...more] = await attachmentResultsOf(fx.prisma, message);
    expect(more).toEqual([]);
    expect(row).toMatchObject({
      verdict: 'clean',
      detectedType: 'pdf',
      sizeBytes: bytes.length,
      clamavSignature: null,
      cacheResult: 'miss',
    });
    expect(codes(row!.reasonCodes)).toEqual(['clean.no_findings']);
    const [delivery] = await waitForAllDeliveries(fx.prisma, org, message.id, ['delivered'], 1);
    expect(delivery!.address).toBe(rcpt.toLowerCase());
    await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete');
    expect(await pathOf(fx.prisma, message)).toEqual(
      DELIVERED_PATH('delivered', 'delivery_complete'),
    );
    expect(await sinkFiles(rcpt)).toHaveLength(1);
    const view = await attachmentEngineView(await messagePublicId(fx.prisma, message));
    expect(view.engine.attachments).toEqual([
      expect.objectContaining({ verdict: 'clean', detectedType: 'pdf', filename: 'statement.pdf' }),
    ]);
    record('attachment-smtp', {
      clean_round_verdict: round.scanVerdict,
      clean_engine_ms: attachmentFinal!.durationMs,
      clean_smtp_to_scanned_ms: scannedAfterMs,
      clean_smtp_to_delivered_ms: Date.now() - started,
    });
  });

  it('a message without attachments: attachment engine skipped (attachment.none), delivered', async () => {
    const { rcpt, message, round, attachmentFinal } = await send(
      'plain',
      'Attachment stack: no attachments',
      [],
    );
    expect(round).toMatchObject({ status: 'completed', requiredEngines: [...REQUIRED_ENGINES] });
    expect(attachmentFinal).toMatchObject({
      outcome: 'skipped',
      attempt: 1,
      reasonCodes: ['attachment.none'],
    });
    expect(await attachmentResultsOf(fx.prisma, message)).toEqual([]);
    await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete');
    expect(await sinkFiles(rcpt)).toHaveLength(1);
    const view = await attachmentEngineView(await messagePublicId(fx.prisma, message));
    expect(view.engine).toMatchObject({ final: true, outcome: 'skipped', attachments: [] });
  });

  it('EICAR inside a zip inside a zip: malicious', async () => {
    const archive = await nestedZip(2, { name: 'payload.txt', data: eicar() });
    const { rcpt, message, round, attachmentFinal } = await send(
      'nested',
      'Attachment stack: nested zip',
      [{ filename: 'documents.zip', contentType: 'application/zip', bytes: archive }],
    );
    expect(round).toMatchObject({ status: 'completed', scanVerdict: 'malicious' });
    expect(attachmentFinal).toMatchObject({ outcome: 'malicious' });
    const [row] = await attachmentResultsOf(fx.prisma, message);
    expect(row).toMatchObject({ verdict: 'malicious', detectedType: 'zip' });
    expect(codes(row!.reasonCodes)).toContain('malware.clamav');
    expect(row!.clamavSignature).toContain(EICAR_CLAMAV_SIGNATURE);
    const archiveInfo = row!.archive as { depthReached: number; entries: number } | null;
    expect(archiveInfo?.depthReached).toBeGreaterThanOrEqual(2);
    // Held like any malicious verdict.
    await sleep(5_000);
    expect((await lifecycleOf(fx.prisma, message)).status).toBe('scanned');
    await expectNotInAnySink(rcpt);
    record('attachment-smtp', {
      nested_verdict: row!.verdict,
      nested_depth: archiveInfo?.depthReached,
      nested_entries: archiveInfo?.entries,
    });
  });

  it('an encrypted zip: suspicious (archive.encrypted), one sandbox submission and its event on scan.sandbox', async () => {
    await purgeDormantQueues(mgmt, vhost);
    const { rcpt, message, round, attachmentFinal } = await send(
      'encrypted',
      'Attachment stack: encrypted zip',
      [{ filename: 'protected.zip', contentType: 'application/zip', bytes: encryptedZip() }],
    );
    expect(round.status).toBe('completed');
    expect(['suspicious', 'spam']).toContain(round.scanVerdict);
    expect(attachmentFinal).toMatchObject({ outcome: 'suspicious' });
    const [row] = await attachmentResultsOf(fx.prisma, message);
    expect(row).toMatchObject({ verdict: 'suspicious', detectedType: 'zip' });
    expect(codes(row!.reasonCodes)).toContain('archive.encrypted');

    // A11: one submission row and its outbox event, written with the final row.
    const [submission, ...moreSubmissions] = await sandboxSubmissionsOf(fx.prisma, message);
    expect(moreSubmissions).toEqual([]);
    expect(submission).toMatchObject({
      organizationId: org,
      scanId: round.id,
      attachmentId: row!.attachmentId,
      partIndex: row!.partIndex,
      sha256: row!.sha256,
      attachmentVerdict: 'suspicious',
      status: 'pending',
    });
    expect(submission!.objectKey.startsWith(`org/${org.toString()}/part/`)).toBe(true);
    const outbox = await fx.prisma.messageOutbox.findFirstOrThrow({
      where: { organizationId: org, eventId: submission!.requestedEventId },
    });
    expect(outbox.eventType).toBe('mail.attachment.sandbox_requested.v1');
    const payload = attachmentSandboxRequestedV1.parse(outbox.payload);
    expect(payload).toMatchObject({
      submissionId: submission!.id.toString(),
      messageId: message.id.toString(),
      scanId: round.id.toString(),
      lifecycleRound: 0,
      attachmentVerdict: 'suspicious',
      attachment: { sha256: row!.sha256, detectedType: 'zip', objectKey: submission!.objectKey },
    });
    expect(JSON.stringify(outbox.payload)).not.toContain('protected.zip');

    // Published by the relay to email.security, bound to the dormant scan.sandbox (step 4.6).
    const routingKey = `org.${org.toString()}.mail.attachment.sandbox_requested.v1`;
    let peeked: { routingKey: string; payload: string }[] = [];
    await eventually(
      async () => {
        peeked = (await mgmt.peek(vhost, 'scan.sandbox', 50)).filter(
          (m) => m.routingKey === routingKey,
        );
        return peeked.length >= 1;
      },
      60_000,
      'the sandbox request on scan.sandbox',
      500,
    );
    expect(peeked).toHaveLength(1);
    const envelope = JSON.parse(peeked[0]!.payload) as { eventId: string; eventType: string };
    expect(envelope).toMatchObject({
      eventId: submission!.requestedEventId,
      eventType: 'mail.attachment.sandbox_requested.v1',
    });

    // The round does not wait for the sandbox; the pass-through approves suspicious.
    await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete');
    expect(await sinkFiles(rcpt)).toHaveLength(1);
    const view = await attachmentEngineView(await messagePublicId(fx.prisma, message));
    expect(view.engine.attachments![0]).toMatchObject({
      verdict: 'suspicious',
      sandbox: { submissionId: submission!.id.toString(), status: 'pending' },
    });
    // Purge the dormant queue (L16); its statistics refresh every few seconds.
    await purgeDormantQueues(mgmt, vhost);
    await eventually(
      async () => (await mgmt.queue(vhost, 'scan.sandbox')).messages === 0,
      20_000,
      'scan.sandbox empty after the purge',
      500,
    );
    record('attachment-smtp', {
      encrypted_verdict: row!.verdict,
      encrypted_reasons: codes(row!.reasonCodes).join(','),
      sandbox_submissions: 1,
      sandbox_events_on_queue: peeked.length,
    });
  });
});
