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
import { attachmentMessage, type MessageAttachment } from './support/attachment-stack';
import { purgeDormantQueues } from './support/broker';
import { waitFor } from './support/compose';
import { waitForAllDeliveries, waitForMessage } from './support/deliveries';
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
  roundFinalEngines,
  sandboxSubmissionsOf,
  scannedEventsOf,
  scanStackGate,
  sendToMx,
  waitForRoundComplete,
} from './support/scan-stack';
import { expectPolicyHeld, floorOf } from './support/policy';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply } from './support/smtp-tools';

/**
 * The step 4.2 attachment engine end to end through the inbound Postfix (docs/plan/steps/
 * 10-attachment-scanning.md §9 "Stack", A1, A3, A6, A11, A15, A16): smtp-tools → postfix:25 →
 * smtp-adapter (EML in MinIO) → email-worker MIME role (part objects + `email_attachments`) →
 * `parsed.v1` → `scan.spam` (Rspamd) and `scan.attachment` (the attachment engine: part object
 * from MinIO, clamd INSTREAM ∥ the inspector child, known hashes, mapper) → round completion →
 * policy-engine (step 5.2: evaluation and approval) → postfix-outbound → mail-sink.
 *
 * - EICAR as a plain attachment: round `completed` with verdict `malicious`, attachment final
 *   `malicious` with `malware.clamav` (ClamAV `Eicar-Test-Signature`); the policy-engine
 *   rejects it (step 5.2: floor `policy.floor.hard_block` → `rejected` / `policy_discard`; before
 *   5.2 the dev pass-through held it in `scanned`), no approval, no delivery, nothing in any
 *   sink; the scans read API (replica) shows the per-attachment row.
 * - A clean PDF-like attachment (unique bytes per run, so never a cache hit of another run): clean
 *   attachment row (`clean.no_findings`, ClamAV OK), approved and delivered.
 * - No attachments: attachment final `skipped` with `attachment.none` (rule A0), delivered.
 * - EICAR inside a zip inside a zip: `malicious`.
 * - An encrypted zip: `suspicious` with `archive.encrypted`, one `sandbox_submissions` row and
 *   one `mail.attachment.sandbox_requested.v1`, which the relay publishes to
 *   `scan.sandbox.submissions` (topology v8, step 4.6 X11) where the email-worker's sandbox
 *   dispatcher consumes it: the fixture organization has no plan feature `attachment_sandbox`,
 *   so the submission ends `skipped` / `feature_disabled` and the round gets a `skipped` sandbox
 *   final (asynchronous: the round verdict is unchanged); suspicious is approved and delivered.
 *
 * Every test file is generated at test time by `@email-gateway/attachment-corpus` (EICAR is
 * assembled from fragments; nothing binary is committed).
 */
const gate = await scanStackGate();
const fx = new SmtpFixtures();
let org = 0n;
let domain: FixtureDomain;
let session: ApiSession | undefined;

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
  it('EICAR attachment: malicious (malware.clamav), rejected by policy (hard-block floor), never delivered', async () => {
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
    expect(roundFinalEngines(finals)).toEqual(['attachment', 'bec', 'dlp', 'rspamd', 'url']);
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

    // A15, since step 5.2: the policy-engine evaluates the scanned event and rejects malicious
    // mail through the hard-block floor (inbound: discarded, no bounce).
    const evaluation = await expectPolicyHeld(fx.prisma, message, { min: 'reject' });
    expect(floorOf(evaluation).reasons).toContain('policy.floor.hard_block');
    await sleep(5_000);
    expect(await lifecycleOf(fx.prisma, message)).toMatchObject({
      status: 'rejected',
      statusReason: 'policy_discard',
      lifecycleRound: 0,
    });
    expect((await pathOf(fx.prisma, message)).slice(-3)).toEqual([
      ['scanning', 'scanned', 'scan_complete'],
      ['scanned', 'policy_evaluated', 'policy_decided'],
      ['policy_evaluated', 'rejected', 'policy_discard'],
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
      eicar_policy: `${evaluation.disposition}:${evaluation.decisionSource}`,
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
    // Held like any malicious verdict (step 5.2: rejected by policy through the hard-block floor,
    // inbound: discarded, no bounce; before 5.2 the dev pass-through left it in `scanned`).
    const evaluation = await expectPolicyHeld(fx.prisma, message, { min: 'reject' });
    expect(floorOf(evaluation).reasons).toContain('policy.floor.hard_block');
    await sleep(5_000);
    expect(await lifecycleOf(fx.prisma, message)).toMatchObject({
      status: 'rejected',
      statusReason: 'policy_discard',
      lifecycleRound: 0,
    });
    expect(
      await fx.prisma.emailDelivery.count({
        where: { organizationId: org, messageId: message.id },
      }),
    ).toBe(0);
    await expectNotInAnySink(rcpt);
    record('attachment-smtp', {
      nested_policy: `${evaluation.disposition}:${evaluation.decisionSource}`,
      nested_verdict: row!.verdict,
      nested_depth: archiveInfo?.depthReached,
      nested_entries: archiveInfo?.entries,
    });
  });

  it('an encrypted zip: suspicious (archive.encrypted), one sandbox submission, dispatched and skipped (no plan feature)', async () => {
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
    const [first, ...moreSubmissions] = await sandboxSubmissionsOf(fx.prisma, message);
    expect(moreSubmissions).toEqual([]);
    expect(first).toMatchObject({
      organizationId: org,
      scanId: round.id,
      attachmentId: row!.attachmentId,
      partIndex: row!.partIndex,
      sha256: row!.sha256,
      attachmentVerdict: 'suspicious',
    });
    expect(first!.objectKey.startsWith(`org/${org.toString()}/part/`)).toBe(true);
    const outbox = await fx.prisma.messageOutbox.findFirstOrThrow({
      where: { organizationId: org, eventId: first!.requestedEventId },
    });
    expect(outbox.eventType).toBe('mail.attachment.sandbox_requested.v1');
    const payload = attachmentSandboxRequestedV1.parse(outbox.payload);
    expect(payload).toMatchObject({
      submissionId: first!.id.toString(),
      messageId: message.id.toString(),
      scanId: round.id.toString(),
      lifecycleRound: 0,
      attachmentVerdict: 'suspicious',
      attachment: { sha256: row!.sha256, detectedType: 'zip', objectKey: first!.objectKey },
    });
    expect(JSON.stringify(outbox.payload)).not.toContain('protected.zip');

    // Topology v8 (step 4.6 X11): the relay publishes it to scan.sandbox.submissions, the
    // email-worker's sandbox dispatcher consumes it. Without the plan feature the submission is
    // skipped (feature_disabled), no analysis or task is created, and the round gets its
    // asynchronous `skipped` sandbox final.
    const submission = await waitFor(
      'the sandbox submission skipped by the dispatcher',
      async () => {
        const [s] = await sandboxSubmissionsOf(fx.prisma, message);
        return s && s.status === 'skipped' ? s : undefined;
      },
      { timeoutMs: 60_000, intervalMs: 500 },
    );
    expect(submission).toMatchObject({
      skipReason: 'feature_disabled',
      analysisId: null,
      sandboxVerdict: null,
    });
    expect(codes(submission.sandboxReasonCodes)).toEqual(['sandbox.feature_disabled']);
    const sandboxFinal = await waitFor(
      'the skipped sandbox final',
      async () =>
        (await engineResultsOf(fx.prisma, message)).find(
          (r) => r.engine === 'sandbox' && r.isFinal,
        ),
      { timeoutMs: 30_000, intervalMs: 500 },
    );
    expect(sandboxFinal).toMatchObject({ outcome: 'skipped', engineVersion: 'sandbox-engine/1' });
    // Asynchronous: the round (already completed) is unchanged by the sandbox final.
    const after = await waitForRoundComplete(fx.prisma, message, 0);
    expect(after).toMatchObject({ scanVerdict: round.scanVerdict, status: 'completed' });
    expect(codes(after.reasonCodes)).toEqual(codes(round.reasonCodes));

    // The round does not wait for the sandbox; policy follows the risk row (allowed here).
    await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete');
    expect(await sinkFiles(rcpt)).toHaveLength(1);
    const view = await attachmentEngineView(await messagePublicId(fx.prisma, message));
    expect(view.engine.attachments![0]).toMatchObject({
      verdict: 'suspicious',
      sandbox: {
        submissionId: submission.id.toString(),
        status: 'skipped',
        skipReason: 'feature_disabled',
        verdict: null,
        executed: null,
      },
    });
    record('attachment-smtp', {
      encrypted_verdict: row!.verdict,
      encrypted_reasons: codes(row!.reasonCodes).join(','),
      sandbox_submissions: 1,
      sandbox_status: submission.status,
      sandbox_skip_reason: submission.skipReason ?? '',
    });
  });
});
