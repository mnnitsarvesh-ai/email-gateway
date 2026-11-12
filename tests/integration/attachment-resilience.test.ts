import { randomInt } from 'node:crypto';
import { pdfLike } from '@email-gateway/attachment-corpus';
import { messageScannedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { idempotencyKey } from './support/api-client';
import { attachmentMessage, clamdResponds } from './support/attachment-stack';
import { purgeDormantQueues } from './support/broker';
import { waitFor } from './support/compose';
import { waitForMessage } from './support/deliveries';
import {
  expectConsistentHistory,
  lifecycleOf,
  pathOf,
  waitForLifecycle,
} from './support/lifecycle';
import { clearSinkDomain, sinkFiles } from './support/mail-sink';
import { record, sleep } from './support/messaging-stack';
import { platformAdminSession, type PlatformAdminSession } from './support/platform-admin';
import { MAIL_SINK_HOST, organizationRef } from './support/routing';
import {
  attachmentResultsOf,
  engineResultsOf,
  ensureEngineRunning,
  REQUIRED_ENGINES,
  roundFinalEngines,
  scannedEventsOf,
  scanRoundsOf,
  scanStackGate,
  sendToMx,
  startEngineService,
  stopEngineService,
  waitForRoundComplete,
} from './support/scan-stack';
import { expectPolicyHeld, floorOf } from './support/policy';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply } from './support/smtp-tools';

/**
 * ClamAV outage through the whole stack (docs/plan/steps/10-attachment-scanning.md §2.0-1, A3,
 * A13, A14, §9 "Stack"). The `clamav` container (clamd + freshclam) is STOPPED:
 *
 * 1. Within the attempt budget: SMTP still accepts (clamd is not on the SMTP path); the
 *    attachment engine records failed attempts (`error`/`timeout`, never final, never `clean`)
 *    while Rspamd's final is already there; clamd is started again (its database load is the
 *    "reload time"), the next attempt gets a definite answer and the round completes `scanned`,
 *    approved and delivered.
 * 2. Past the budget (`SCAN_ATTACHMENT_MAX_ATTEMPTS`): the attachment engine's last attempt is
 *    final `error`, the round `failed`, the message `scan_failed`, never approved or delivered;
 *    since step 5.2 the policy-engine then quarantines it (E9 `scan_failed_fail_safe`, floor
 *    `policy.floor.scan_failed`, E11 `policy_quarantine`).
 * 3. Rescan through the admin API job (`POST /api/v1/platform/attachment-rescans`, A13, platform
 *    admin with MFA) after clamd is back: the email-worker's rescan runner selects the message
 *    (window, organization, `quarantined` since step 5.2, has attachments) and moves it through
 *    E19 (`scanner`, `signature_rescan`) into round 1, which is scanned with new rows (round 0
 *    unchanged), evaluated, approved and delivered; the job ends `completed` with one requested
 *    message.
 *
 * Every attachment is unique per run (random seed), so no content-cache entry (A10) answers in
 * place of clamd. `afterAll` always starts clamd again and waits for its health check. One clamd
 * only (8 GB VM): the suite never starts a second instance.
 */
const gate = await scanStackGate();
const fx = new SmtpFixtures();
let org = 0n;
let orgPublicId = '';
let domain: FixtureDomain;
let admin: PlatformAdminSession | undefined;
let failedMessage: { id: bigint; receivedAt: Date } | undefined;
const maxAttempts = Number(process.env.SCAN_ATTACHMENT_MAX_ATTEMPTS ?? 6);
const CLAMD_START_TIMEOUT_MS = 600_000;

beforeAll(async () => {
  assertStackReady(gate);
  org = await fx.organization('att-res');
  orgPublicId = (await organizationRef(fx, org)).publicId;
  domain = await fx.domain(org, 'att-res');
  await fx.destinations(domain, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  admin = await platformAdminSession(fx.prisma);
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  await ensureEngineRunning('clamav', CLAMD_START_TIMEOUT_MS).catch(() => undefined);
  await admin?.remove();
  if (domain) await clearSinkDomain(domain.name).catch(() => undefined);
  await fx.cleanup();
  await purgeDormantQueues();
}, CLAMD_START_TIMEOUT_MS + 120_000);

async function sendWithAttachment(local: string, subject: string) {
  const rcpt = `${local}@${domain.name}`;
  const bytes = pdfLike(32 * 1024, randomInt(1, 2 ** 31));
  const built = attachmentMessage({
    from: 'alice@clean.scan.test',
    to: [rcpt],
    subject,
    attachments: [{ filename: 'report.pdf', contentType: 'application/pdf', bytes }],
  });
  const started = Date.now();
  const sent = await sendToMx({
    from: 'alice@clean.scan.test',
    to: [rcpt],
    helo: 'mx.clean.scan.test',
    data: built.text,
  });
  return { rcpt, sent, smtpMs: Date.now() - started };
}

const attachmentRows = async (message: { id: bigint; receivedAt: Date }) =>
  (await engineResultsOf(fx.prisma, message)).filter((r) => r.engine === 'attachment');

/** Starts clamd and waits until it answers PING (database loaded); seconds it took. */
async function startClamd(): Promise<number> {
  const started = Date.now();
  await startEngineService('clamav', CLAMD_START_TIMEOUT_MS);
  await waitFor('clamd answers PING', () => clamdResponds(), {
    timeoutMs: 120_000,
    intervalMs: 1_000,
  });
  return (Date.now() - started) / 1000;
}

function expectFailedAttempts(rows: Awaited<ReturnType<typeof attachmentRows>>): void {
  for (const a of rows) {
    expect(['error', 'timeout']).toContain(a.outcome);
    expect(a.errorCode).not.toBeNull();
    expect(a.reasonCodes as string[]).toEqual([
      expect.stringMatching(/^engine\.(error|timeout|circuit_open|protocol_error)$/),
    ]);
  }
}

describe.skipIf(gate.skip)('attachment stack: ClamAV outage', { timeout: 900_000 }, () => {
  it('accepts at SMTP time while clamd is down, records failed attempts (never clean), and completes once clamd is back', async () => {
    await stopEngineService('clamav');
    let restartS = 0;
    try {
      const { rcpt, sent, smtpMs } = await sendWithAttachment('recover', 'ClamAV down: recovery');
      expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
      const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
      const failed = await waitFor(
        'a failed attachment-engine attempt',
        async () => {
          const rows = await attachmentRows(message);
          return rows.length > 0 ? rows : undefined;
        },
        { timeoutMs: 120_000, intervalMs: 250 },
      );
      expect(failed.every((r) => !r.isFinal)).toBe(true);
      expectFailedAttempts(failed);
      expect(await attachmentResultsOf(fx.prisma, message)).toEqual([]);
      expect((await lifecycleOf(fx.prisma, message)).status).toBe('scanning');
      restartS = await startClamd();

      const round = await waitForRoundComplete(fx.prisma, message, 0, 300_000);
      const rows = await attachmentRows(message);
      const attempts = rows.filter((r) => !r.isFinal);
      const finals = rows.filter((r) => r.isFinal);
      expect(round.requiredEngines).toEqual([...REQUIRED_ENGINES]);
      expect(
        round.status,
        JSON.stringify(rows.map((r) => [r.attempt, r.outcome, r.errorCode])),
      ).toBe('completed');
      expect(finals).toHaveLength(1);
      expect(finals[0]).toMatchObject({ outcome: 'clean', attempt: attempts.length + 1 });
      expect(attempts.length).toBeGreaterThanOrEqual(1);
      expect(attempts.length + 1).toBeLessThanOrEqual(maxAttempts);
      expectFailedAttempts(attempts);
      expect(attempts.map((a) => a.attempt)).toEqual(attempts.map((_, i) => i + 1));
      const [result] = await attachmentResultsOf(fx.prisma, message);
      expect(result).toMatchObject({ verdict: 'clean', cacheResult: 'miss' });
      const [scanned] = await scannedEventsOf(fx.prisma, org, message);
      expect(messageScannedV1.parse(scanned!.payload).engines).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ engine: 'attachment', attempts: attempts.length + 1 }),
        ]),
      );
      await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete');
      expect(await sinkFiles(rcpt)).toHaveLength(1);
      record('attachment-resilience', {
        smtp_accept_ms_clamd_down: smtpMs,
        clamd_restart_s: restartS.toFixed(1),
        failed_attempts_before_recovery: attempts.length,
        attempt_codes: attempts.map((a) => a.errorCode).join(','),
        recovered_attachment_verdict: result!.verdict,
      });
    } finally {
      await ensureEngineRunning('clamav', CLAMD_START_TIMEOUT_MS);
    }
  });

  it('ends scan_failed (never clean, never approved or delivered; quarantined by policy) when clamd stays down past the attempt budget', async () => {
    await stopEngineService('clamav');
    const stoppedAt = Date.now();
    let downForS = 0;
    try {
      const { rcpt, sent } = await sendWithAttachment('failed', 'ClamAV down: budget exhausted');
      expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
      const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
      const round = await waitForRoundComplete(fx.prisma, message, 0, 600_000);
      downForS = (Date.now() - stoppedAt) / 1000;
      expect(round).toMatchObject({ status: 'failed', scanVerdict: 'error' });
      const rows = await attachmentRows(message);
      expect(rows).toHaveLength(maxAttempts);
      expect(rows.map((r) => r.attempt)).toEqual(rows.map((_, i) => i + 1));
      expect(rows.filter((r) => r.isFinal).map((r) => r.attempt)).toEqual([maxAttempts]);
      expectFailedAttempts(rows);
      // Never clean: no per-attachment row is written for a failed final (A12).
      expect(await attachmentResultsOf(fx.prisma, message)).toEqual([]);
      const [scanned] = await scannedEventsOf(fx.prisma, org, message);
      const payload = messageScannedV1.parse(scanned!.payload);
      expect(payload).toMatchObject({ outcome: 'scan_failed', verdict: 'error' });
      expect(payload.engines).toEqual(
        expect.arrayContaining([
          { engine: 'attachment', required: true, outcome: 'error', attempts: maxAttempts },
        ]),
      );
      // Step 5.2: the policy-engine evaluates the scan_failed round (E9) and holds it: floor
      // `scan_failed`, at least quarantine (E11), never an approval.
      const evaluation = await expectPolicyHeld(fx.prisma, message, { min: 'quarantine' });
      expect(evaluation).toMatchObject({ trigger: 'scan_failed', disposition: 'quarantine' });
      expect(floorOf(evaluation).reasons).toContain('policy.floor.scan_failed');
      expect((await pathOf(fx.prisma, message)).slice(3)).toEqual([
        ['scanning', 'scan_failed', 'scan_error'],
        ['scan_failed', 'policy_evaluated', 'scan_failed_fail_safe'],
        ['policy_evaluated', 'quarantined', 'policy_quarantine'],
      ]);
      await sleep(5_000);
      expect(
        await fx.prisma.emailDelivery.count({
          where: { organizationId: org, messageId: message.id },
        }),
      ).toBe(0);
      expect(await lifecycleOf(fx.prisma, message)).toMatchObject({
        status: 'quarantined',
        statusReason: 'policy_quarantine',
        lifecycleRound: 0,
      });
      expect(await sinkFiles(rcpt)).toEqual([]);
      failedMessage = { id: message.id, receivedAt: message.receivedAt };
      record('attachment-resilience', {
        attempts_until_scan_failed: rows.length,
        scan_failed_after_s: downForS.toFixed(1),
        final_error_code: rows.at(-1)!.errorCode,
      });
    } finally {
      await ensureEngineRunning('clamav', CLAMD_START_TIMEOUT_MS);
      await waitFor('clamd answers PING', () => clamdResponds(), {
        timeoutMs: 120_000,
        intervalMs: 1_000,
      });
    }
  });

  it('rescans the scan_failed (now quarantined) message through an admin rescan job: round 1 is scanned, round 0 unchanged', async () => {
    expect(failedMessage, 'the previous case left a quarantined scan_failed message').toBeDefined();
    const message = failedMessage!;
    const rcpt = `failed@${domain.name}`;
    const round0Before = await scanRoundsOf(fx.prisma, message);
    const rows0Before = await engineResultsOf(fx.prisma, message);

    const dry = await admin!.call(
      'POST',
      '/platform/attachment-rescans',
      {
        windowHours: 1,
        states: ['quarantined'],
        organizationId: orgPublicId,
        reason: 'stack test: clamd recovered (dry run)',
        dryRun: true,
      },
      idempotencyKey(),
    );
    expect(dry.status, JSON.stringify(dry.body)).toBe(200);
    expect(dry.body).toMatchObject({ dryRun: true, estimatedMessages: 1 });

    const created = await admin!.call(
      'POST',
      '/platform/attachment-rescans',
      {
        windowHours: 1,
        states: ['quarantined'],
        organizationId: orgPublicId,
        reason: 'stack test: clamd recovered',
      },
      idempotencyKey(),
    );
    expect(created.status, JSON.stringify(created.body)).toBe(202);
    expect(created.body).toMatchObject({ status: 'pending', estimatedMessages: 1 });
    const jobId = created.body.jobId as string;

    const round1 = await waitForRoundComplete(fx.prisma, message, 1, 300_000);
    expect(round1).toMatchObject({
      scanKind: 'rescan',
      status: 'completed',
      requiredEngines: [...REQUIRED_ENGINES],
    });
    const job = await waitFor(
      `rescan job ${jobId} completed`,
      async () => {
        const res = await admin!.call('GET', `/platform/attachment-rescans/${jobId}`);
        return res.status === 200 && res.body.status === 'completed' ? res.body : undefined;
      },
      { timeoutMs: 120_000, intervalMs: 1_000 },
    );
    expect(job).toMatchObject({
      trigger: 'admin',
      organizationId: orgPublicId,
      selectedCount: 1,
      requestedCount: 1,
      requestedByUserId: admin!.userPublicId,
    });
    const all = await engineResultsOf(fx.prisma, message);
    const round1Finals = all.filter((r) => r.scanId === round1.id && r.isFinal);
    expect(roundFinalEngines(round1Finals)).toEqual(['attachment', 'bec', 'dlp', 'rspamd', 'url']);
    expect(round1Finals.find((r) => r.engine === 'attachment')!.outcome).toBe('clean');
    const results = await attachmentResultsOf(fx.prisma, message);
    expect(results.map((r) => [r.scanId, r.verdict])).toEqual([[round1.id, 'clean']]);
    // Round 0 is never touched by round 1.
    const rounds = await scanRoundsOf(fx.prisma, message);
    expect(rounds.map((r) => r.lifecycleRound)).toEqual([0, 1]);
    expect(rounds[0]).toEqual(round0Before[0]);
    expect(all.filter((r) => r.scanId === round0Before[0]!.id)).toEqual(rows0Before);

    await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete');
    expect((await pathOf(fx.prisma, message)).slice(2)).toEqual([
      ['persisted', 'scanning', 'scan_started'],
      ['scanning', 'scan_failed', 'scan_error'],
      ['scan_failed', 'policy_evaluated', 'scan_failed_fail_safe'],
      ['policy_evaluated', 'quarantined', 'policy_quarantine'],
      ['quarantined', 'scanning', 'signature_rescan'],
      ['scanning', 'scanned', 'scan_complete'],
      ['scanned', 'policy_evaluated', 'policy_decided'],
      ['policy_evaluated', 'approved', 'policy_deliver'],
      ['approved', 'delivery_pending', 'delivery_planned'],
      ['delivery_pending', 'delivered', 'delivery_complete'],
    ]);
    await expectConsistentHistory(fx.prisma, message);
    expect(await sinkFiles(rcpt)).toHaveLength(1);
    record('attachment-resilience', {
      rescan_job_requested: job.requestedCount,
      rescan_round1_verdict: round1.scanVerdict,
    });
  });
});
