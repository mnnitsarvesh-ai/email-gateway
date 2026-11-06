import { messageScannedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, type ApiSession } from './support/api-client';
import { purgeDormantQueues } from './support/broker';
import { waitFor } from './support/compose';
import { waitForMessage } from './support/deliveries';
import { stack } from './support/env';
import {
  expectConsistentHistory,
  lifecycleOf,
  pathOf,
  waitForLifecycle,
} from './support/lifecycle';
import { clearSinkDomain, sinkFiles } from './support/mail-sink';
import { buildMessage } from './support/messages';
import { record } from './support/messaging-stack';
import { MAIL_SINK_HOST, organizationRef, sleep } from './support/routing';
import {
  engineResultsOf as allEngineResultsOf,
  ensureRspamdRunning,
  messagePublicId,
  REQUIRED_ENGINES,
  scannedEventsOf,
  scanRoundsOf,
  scanStackGate,
  sendToMx,
  startRspamd,
  stopRspamd,
  waitForEngineRows,
  waitForRoundComplete,
} from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply } from './support/smtp-tools';

/**
 * Engine failure through the whole stack (docs/plan/steps/09-rspamd.md §2.0-1, S10, S11, S14,
 * §9 "Stack"). The inbound Rspamd container is STOPPED, which takes away both its roles at once:
 *
 * 1. Within the attempt budget: SMTP still accepts (`milter_default_action = accept`, ADR-0027),
 *    the post-queue scan records failed attempts (`error`/`timeout`, never final, never clean)
 *    and retries with backoff; Rspamd is started again before the budget is spent, the next
 *    attempt gets a real result, the round ends `scanned`, the pass-through approves and the
 *    message is delivered.
 * 2. Past the budget (`SCAN_RSPAMD_MAX_ATTEMPTS`, about a minute with the defaults): the last
 *    attempt is final `error`, the round `failed` with verdict `error`, the message
 *    `scan_failed/scan_error`, `scanned.v1` says `scan_failed`, and the pass-through never
 *    approves it (no approval, no delivery). Rspamd is started again afterwards.
 * 3. Administrative rescan of that message through the api (E19): round 1 is scanned with a new
 *    result, round 0's rows stay exactly as they were, and round 1 is approved and delivered.
 *
 * `afterAll` always starts Rspamd again and waits for its health check.
 *
 * Step 4.2: every round also requires the `attachment` engine (A1); these messages have no
 * attachments, so its final is `skipped` (`attachment.none`, rule A0) at the first attempt and
 * the assertions on attempts below are about the Rspamd rows. The ClamAV outage is
 * attachment-resilience.test.ts.
 */
const gate = await scanStackGate();
const fx = new SmtpFixtures();
let org = 0n;
let domain: FixtureDomain;
let session: ApiSession | undefined;
let failedMessage: { id: bigint; receivedAt: Date; publicId: string } | undefined;
const maxAttempts = Number(process.env.SCAN_RSPAMD_MAX_ATTEMPTS ?? 6);

/** The Rspamd rows of a message (attempts and finals). */
async function engineResultsOf(
  prisma: typeof fx.prisma,
  message: { id: bigint; receivedAt: Date },
) {
  return (await allEngineResultsOf(prisma, message)).filter((r) => r.engine === 'rspamd');
}

/** The attachment engine's single final of every round: `skipped`, `attachment.none`. */
async function expectAttachmentSkipped(message: { id: bigint; receivedAt: Date }, rounds: number) {
  const rows = (await allEngineResultsOf(fx.prisma, message)).filter(
    (r) => r.engine === 'attachment',
  );
  expect(rows.map((r) => [r.isFinal, r.attempt, r.outcome, r.reasonCodes])).toEqual(
    Array.from({ length: rounds }, () => [true, 1, 'skipped', ['attachment.none']]),
  );
}

beforeAll(async () => {
  assertStackReady(gate);
  org = await fx.organization('scan-res');
  domain = await fx.domain(org, 'scan-res');
  await fx.destinations(domain, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  session = await apiSession(fx.prisma, await organizationRef(fx, org), 'security_analyst');
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  await ensureRspamdRunning().catch(() => undefined);
  await session?.remove();
  if (domain) await clearSinkDomain(domain.name).catch(() => undefined);
  await fx.cleanup();
  await purgeDormantQueues();
}, 300_000);

async function sendPlain(rcpt: string, subject: string) {
  const built = buildMessage({ from: 'alice@clean.scan.test', to: [rcpt], subject });
  const started = Date.now();
  const sent = await sendToMx({
    from: 'alice@clean.scan.test',
    to: [rcpt],
    helo: 'mx.clean.scan.test',
    data: built.text,
  });
  return { sent, smtpMs: Date.now() - started };
}

/** Approval outbox rows of one message (any source). */
async function approvalsOf(messageId: bigint): Promise<number> {
  const rows = await fx.prisma.messageOutbox.findMany({
    where: { organizationId: org, eventType: 'mail.delivery.approved.v1' },
    select: { payload: true },
  });
  return rows.filter(
    (r) => (r.payload as { messageId?: string }).messageId === messageId.toString(),
  ).length;
}

async function skippedScanFailed(): Promise<number | undefined> {
  try {
    const res = await fetch(
      `http://${stack.host}:${stack.ports.services['delivery-worker']}/metrics`,
      { signal: AbortSignal.timeout(5_000) },
    );
    const line = (await res.text())
      .split('\n')
      .find(
        (l) =>
          l.startsWith('delivery_approvals_skipped_total{') && l.includes('reason="scan_failed"'),
      );
    return line ? Number(line.split(' ').at(-1)) : 0;
  } catch {
    return undefined;
  }
}

describe.skipIf(gate.skip)('scan stack: Rspamd outage', { timeout: 600_000 }, () => {
  it('accepts at SMTP time while Rspamd is down, retries, and scans once Rspamd is back within the budget', async () => {
    const rcpt = `recover@${domain.name}`;
    await stopRspamd();
    let restartS = 0;
    try {
      const { sent, smtpMs } = await sendPlain(rcpt, 'Scan resilience: recovery');
      // Milter unreachable → default action accept (no tempfail).
      expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
      const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
      await waitForEngineRows(fx.prisma, message, 1);
      const failed = await waitFor(
        'a failed Rspamd attempt',
        async () => {
          const rows = await engineResultsOf(fx.prisma, message);
          return rows.length > 0 ? rows : undefined;
        },
        { timeoutMs: 120_000, intervalMs: 250 },
      );
      expect(failed.every((r) => !r.isFinal)).toBe(true);
      expect(failed.every((r) => r.outcome === 'error' || r.outcome === 'timeout')).toBe(true);
      expect((await lifecycleOf(fx.prisma, message)).status).toBe('scanning');
      restartS = await startRspamd();

      const round = await waitForRoundComplete(fx.prisma, message, 0, 180_000);
      expect(round.status).toBe('completed');
      const rows = await engineResultsOf(fx.prisma, message);
      const attempts = rows.filter((r) => !r.isFinal);
      const finals = rows.filter((r) => r.isFinal);
      expect(finals).toHaveLength(1);
      expect(attempts.length).toBeGreaterThanOrEqual(1);
      // Every failed attempt is error/timeout with an engine reason; none is ever clean.
      for (const a of attempts) {
        expect(['error', 'timeout']).toContain(a.outcome);
        expect(a.errorCode).not.toBeNull();
        expect(a.reasonCodes as string[]).toEqual([
          expect.stringMatching(/^engine\.(error|timeout|circuit_open|protocol_error)$/),
        ]);
      }
      expect(attempts.map((a) => a.attempt)).toEqual(attempts.map((_, i) => i + 1));
      expect(finals[0]!.attempt).toBe(attempts.length + 1);
      expect(attempts.length + 1).toBeLessThanOrEqual(maxAttempts);
      expect(['error', 'timeout']).not.toContain(finals[0]!.outcome);
      expect(round.scanVerdict).toBe(finals[0]!.outcome);
      expect(round.requiredEngines).toEqual([...REQUIRED_ENGINES]);
      await expectAttachmentSkipped(message, 1);
      const [scanned] = await scannedEventsOf(fx.prisma, org, message);
      const recovered = messageScannedV1.parse(scanned!.payload);
      expect(recovered.outcome).toBe('scanned');
      expect(recovered.engines).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ engine: 'rspamd', attempts: attempts.length + 1 }),
          expect.objectContaining({ engine: 'attachment', outcome: 'skipped', attempts: 1 }),
        ]),
      );

      await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete');
      expect((await pathOf(fx.prisma, message)).slice(2, 5)).toEqual([
        ['persisted', 'scanning', 'scan_started'],
        ['scanning', 'scanned', 'scan_complete'],
        ['scanned', 'approved', 'dev_passthrough'],
      ]);
      expect(await sinkFiles(rcpt)).toHaveLength(1);
      record('scan-resilience', {
        smtp_accept_ms_rspamd_down: smtpMs,
        rspamd_restart_s: restartS.toFixed(1),
        failed_attempts_before_recovery: attempts.length,
        attempt_codes: attempts.map((a) => a.errorCode).join(','),
        recovered_verdict: round.scanVerdict,
      });
    } finally {
      await ensureRspamdRunning();
    }
  });

  it('ends scan_failed (never clean, never approved or delivered) when Rspamd stays down past the attempt budget', async () => {
    const rcpt = `failed@${domain.name}`;
    const skippedBefore = await skippedScanFailed();
    await stopRspamd();
    let downForS = 0;
    const stoppedAt = Date.now();
    try {
      const { sent } = await sendPlain(rcpt, 'Scan resilience: budget exhausted');
      expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
      const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
      const round = await waitForRoundComplete(fx.prisma, message, 0, 300_000);
      downForS = (Date.now() - stoppedAt) / 1000;
      expect(round).toMatchObject({ status: 'failed', scanVerdict: 'error' });
      expect(round.reasonCodes as string[]).toEqual(
        expect.arrayContaining([expect.stringMatching(/^engine\./)]),
      );
      const rows = await engineResultsOf(fx.prisma, message);
      expect(rows).toHaveLength(maxAttempts);
      expect(rows.map((r) => r.attempt)).toEqual(rows.map((_, i) => i + 1));
      expect(rows.filter((r) => r.isFinal).map((r) => r.attempt)).toEqual([maxAttempts]);
      // Never clean: every row, final or not, is a failure.
      expect(rows.every((r) => r.outcome === 'error' || r.outcome === 'timeout')).toBe(true);
      expect(rows.every((r) => r.errorCode !== null)).toBe(true);
      await expectAttachmentSkipped(message, 1);
      await waitForLifecycle(fx.prisma, message, 'scan_failed', 'scan_error');
      const [scanned] = await scannedEventsOf(fx.prisma, org, message);
      const failedPayload = messageScannedV1.parse(scanned!.payload);
      expect(failedPayload).toMatchObject({ outcome: 'scan_failed', verdict: 'error' });
      expect(failedPayload.engines).toEqual(
        expect.arrayContaining([
          { engine: 'rspamd', required: true, outcome: 'error', attempts: maxAttempts },
          { engine: 'attachment', required: true, outcome: 'skipped', attempts: 1 },
          expect.objectContaining({ engine: 'url', required: true }),
        ]),
      );
      expect(failedPayload.engines).toHaveLength(REQUIRED_ENGINES.length);

      // The pass-through skips it: no approval, no delivery, the state stays scan_failed.
      await waitFor(
        'the pass-through to skip the scan_failed message',
        async () => {
          const after = await skippedScanFailed();
          return after === undefined || skippedBefore === undefined || after > skippedBefore;
        },
        { timeoutMs: 30_000, intervalMs: 1_000 },
      );
      await sleep(10_000);
      expect(await approvalsOf(message.id)).toBe(0);
      expect(
        await fx.prisma.emailDelivery.count({
          where: { organizationId: org, messageId: message.id },
        }),
      ).toBe(0);
      expect(await lifecycleOf(fx.prisma, message)).toMatchObject({
        status: 'scan_failed',
        statusReason: 'scan_error',
        lifecycleRound: 0,
      });
      expect(await sinkFiles(rcpt)).toEqual([]);
      await expectConsistentHistory(fx.prisma, message);
      failedMessage = {
        id: message.id,
        receivedAt: message.receivedAt,
        publicId: await messagePublicId(fx.prisma, message),
      };
      record('scan-resilience', {
        attempts_until_scan_failed: rows.length,
        scan_failed_after_s: downForS.toFixed(1),
        final_error_code: rows.at(-1)!.errorCode,
        skipped_scan_failed_delta:
          skippedBefore === undefined ? 'n/a' : ((await skippedScanFailed()) ?? 0) - skippedBefore,
      });
    } finally {
      await ensureRspamdRunning();
    }
  });

  it('rescans the scan_failed message through the api: round 1 gets a new result, round 0 is unchanged', async () => {
    expect(failedMessage, 'the previous case left a scan_failed message').toBeDefined();
    const message = failedMessage!;
    const rcpt = `failed@${domain.name}`;
    const round0Before = await scanRoundsOf(fx.prisma, message);
    const rows0Before = await engineResultsOf(fx.prisma, message);
    const current = await lifecycleOf(fx.prisma, message);

    const res = await session!.post(
      `/messages/${message.publicId}/rescan`,
      { expectedVersion: current.version, reason: 'stack test: rspamd recovered' },
      { 'Idempotency-Key': `it-scan-rescan-${fx.suffix}` },
    );
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body).toMatchObject({ state: 'scanning', lifecycleRound: 1 });
    const rescanEventId = (res.body as { rescanEventId: string }).rescanEventId;

    const round1 = await waitForRoundComplete(fx.prisma, message, 1, 180_000);
    expect(round1).toMatchObject({
      scanKind: 'rescan',
      status: 'completed',
      triggerEventId: rescanEventId,
      requiredEngines: [...REQUIRED_ENGINES],
    });
    expect(['error', 'timeout']).not.toContain(round1.scanVerdict);
    await expectAttachmentSkipped(message, 2);
    const all = await engineResultsOf(fx.prisma, message);
    const round1Rows = all.filter((r) => r.scanId === round1.id);
    expect(round1Rows.filter((r) => r.isFinal)).toHaveLength(1);
    expect(['error', 'timeout']).not.toContain(round1Rows.find((r) => r.isFinal)!.outcome);
    // Round 0 is never touched by round 1.
    const rounds = await scanRoundsOf(fx.prisma, message);
    expect(rounds.map((r) => r.lifecycleRound)).toEqual([0, 1]);
    expect(rounds[0]).toEqual(round0Before[0]);
    expect(all.filter((r) => r.scanId === round0Before[0]!.id)).toEqual(rows0Before);
    const scanned = await scannedEventsOf(fx.prisma, org, message);
    expect(
      scanned
        .map((e) => messageScannedV1.parse(e.payload))
        .map((p) => [p.lifecycleRound, p.outcome]),
    ).toEqual([
      [0, 'scan_failed'],
      [1, 'scanned'],
    ]);

    // Round 1 is approved (E27 with expectedRound 1) and delivered.
    await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete');
    expect((await pathOf(fx.prisma, message)).slice(2)).toEqual([
      ['persisted', 'scanning', 'scan_started'],
      ['scanning', 'scan_failed', 'scan_error'],
      ['scan_failed', 'scanning', 'admin_rescan'],
      ['scanning', 'scanned', 'scan_complete'],
      ['scanned', 'approved', 'dev_passthrough'],
      ['approved', 'delivery_pending', 'delivery_planned'],
      ['delivery_pending', 'delivered', 'delivery_complete'],
    ]);
    await expectConsistentHistory(fx.prisma, message);
    expect(await sinkFiles(rcpt)).toHaveLength(1);

    // The read API lists both rounds, newest first.
    const page = await waitFor(
      'both rounds in the scans read API',
      async () => {
        const r = await session!.get(`/messages/${message.publicId}/scans`);
        const body = r.body as { data?: { round: number; status: string; verdict: string }[] };
        return r.status === 200 && body.data?.length === 2 && body.data[0]!.status !== 'running'
          ? body
          : undefined;
      },
      { timeoutMs: 30_000, intervalMs: 500 },
    );
    expect(page.data!.map((r) => [r.round, r.status])).toEqual([
      [1, 'completed'],
      [0, 'failed'],
    ]);
    expect(page.data![1]!.verdict).toBe('error');
    record('scan-resilience', { rescan_verdict: round1.scanVerdict });
  });
});
