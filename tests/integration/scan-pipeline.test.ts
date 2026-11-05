import { randomUUID } from 'node:crypto';
import { messageScannedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, type ApiSession } from './support/api-client';
import { ManagementApi, purgeDormantQueues } from './support/broker';
import { waitFor } from './support/compose';
import { stack } from './support/env';
import { waitForAllDeliveries, waitForMessage } from './support/deliveries';
import {
  DELIVERED_PATH,
  expectConsistentHistory,
  expectStateChangedRows,
  historyOf,
  pathOf,
  waitForLifecycle,
} from './support/lifecycle';
import { clearSinkDomain, sinkFiles, sinkMessage } from './support/mail-sink';
import { metricValue } from './support/metrics';
import { envelopeOfRow, LiveBroker, QUEUES, record, sleep } from './support/messaging-stack';
import { MAIL_SINK_HOST, organizationRef } from './support/routing';
import {
  authResultsOf,
  corpusEml,
  engineResultsOf,
  gatewayAuthservId,
  headerFieldsOf,
  ATTACHMENT_LEDGER,
  messagePublicId,
  REQUIRED_ENGINES,
  RSPAMD_LEDGER,
  scannedEventsOf,
  scanRoundsOf,
  scanStackGate,
  sendToMx,
  waitForRoundComplete,
} from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply } from './support/smtp-tools';

/**
 * The step 4.1 scan pipeline end to end through the inbound Postfix (docs/plan/steps/
 * 09-rspamd.md §9 "Stack", S2–S7, S15): smtp-tools → postfix:25 (milter) → smtp-adapter (EML in
 * MinIO) → event-relay → `email.received` → email-worker MIME role (`parsed.v1`) → event-relay →
 * `scan.spam` → email-worker scan role (Rspamd `/checkv2` with the trusted envelope; round 0
 * opened with E3, completed with E6 and `mail.message.scanned.v1` in the same transaction) →
 * dev pass-through (outbox feed of `scanned.v1`, E27) → planner → postfix-outbound → mail-sink.
 *
 * - A clean, DKIM-signed and SPF/DMARC-aligned message ends `scanned` with a `clean` Rspamd
 *   result (`email_scans`, one final `scan_engine_results` row, `email_auth_results`, one
 *   `scanned.v1` outbox row, one scan ledger row), is approved by the pass-through and delivered.
 * - A message spoofing `spoof.scan.test` from the mailtest network (not in its SPF; DMARC
 *   p=reject) is accepted at SMTP time (DMARC reject is not enforced there by default, ADR-0027)
 *   and scanned with `auth.spf_fail` and `auth.dmarc_reject`; a forged `Authentication-Results`
 *   claiming a pass is ignored.
 * - Duplicate scan triggers (§2.0-4): exact copies of the clean message's real `parsed.v1`
 *   (same event id, published as the relay does) are ledger duplicates, and a re-emission with a
 *   new event id is skipped by the lifecycle check; no second round, result, transition,
 *   `scanned.v1`, approval or delivery, and no dead letter.
 * - Topology v4: `scan.spam` and `scan.attachment` consumed by the scanner role user, `scan.auth`
 *   without event bindings.
 *
 * Since step 4.2 every round also requires the `attachment` engine (A1): the messages of this
 * suite have no attachments, so its final is `skipped` with `attachment.none` (rule A0), which
 * never decides the verdict (Rspamd does). Attachments through the stack are
 * attachment-smtp.test.ts.
 */
const gate = await scanStackGate();
const fx = new SmtpFixtures();
let org = 0n;
let domain: FixtureDomain;
let session: ApiSession | undefined;
let authservId = '';
let cleanMessage: { id: bigint; receivedAt: Date; rcpt: string } | undefined;
const mgmt = new ManagementApi();
const vhost = stack.rabbitmqVhost();

beforeAll(async () => {
  assertStackReady(gate);
  org = await fx.organization('scan-pipe');
  domain = await fx.domain(org, 'scan-pipe');
  await fx.destinations(domain, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  session = await apiSession(fx.prisma, await organizationRef(fx, org), 'security_analyst');
  authservId = await gatewayAuthservId();
}, 120_000);

afterAll(async () => {
  if (gate.skip) return;
  await session?.remove();
  if (domain) await clearSinkDomain(domain.name).catch(() => undefined);
  await fx.cleanup();
  await purgeDormantQueues();
}, 120_000);

/** The `scans` read API (replica) once it shows `rounds` rounds. */
async function scansApi(publicId: string, rounds: number) {
  return waitFor(
    `GET /messages/${publicId}/scans with ${rounds} completed round(s)`,
    async () => {
      const res = await session!.get(`/messages/${publicId}/scans`);
      if (res.status !== 200) return undefined;
      const body = res.body as {
        data: { round: number; status: string; engines: { final: boolean }[] }[];
      };
      return body.data.length === rounds && body.data.every((r) => r.status !== 'running')
        ? (res.body as Record<string, unknown>)
        : undefined;
    },
    { timeoutMs: 30_000, intervalMs: 500 },
  );
}

describe.skipIf(gate.skip)('scan stack: pipeline through Postfix', { timeout: 300_000 }, () => {
  it('scans a clean message (clean, SPF/DKIM/DMARC pass), then the pass-through approves and delivers it', async () => {
    const rcpt = `clean@${domain.name}`;
    const started = Date.now();
    const sent = await sendToMx({
      from: 'alice@clean.scan.test',
      to: [rcpt],
      helo: 'mx.clean.scan.test',
      data: corpusEml('clean/clean-dkim-aligned.eml'),
    });
    expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
    const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });

    const round = await waitForRoundComplete(fx.prisma, message, 0);
    const scannedAfterMs = Date.now() - started;
    const parsed = await fx.prisma.messageOutbox.findFirstOrThrow({
      where: {
        organizationId: org,
        aggregateId: message.id.toString(),
        eventType: 'mail.message.parsed.v1',
      },
    });
    expect(round).toMatchObject({
      organizationId: org,
      lifecycleRound: 0,
      scanKind: 'initial',
      status: 'completed',
      scanVerdict: 'clean',
      requiredEngines: [...REQUIRED_ENGINES],
      triggerEventId: parsed.eventId,
      attempt: 1,
    });
    expect(round.deadlineAt!.getTime()).toBeGreaterThan(round.startedAt!.getTime());
    expect(round.reasonCodes).toContain('clean.below_threshold');

    const results = await engineResultsOf(fx.prisma, message);
    expect(results).toHaveLength(2);
    const final = results.find((r) => r.engine === 'rspamd');
    expect(final).toMatchObject({
      scanId: round.id,
      engine: 'rspamd',
      isFinal: true,
      finalEngine: 'rspamd',
      attempt: 1,
      outcome: 'clean',
      errorCode: null,
    });
    expect(final!.engineVersion).toMatch(/^\d+\.\d+\.\d+/);
    expect(final!.settingsVersion).toMatch(/^rspamd-map\/2;p=[0-9a-f]{12};t=none$/);
    expect(Number(final!.score)).toBeLessThan(4);
    expect(final!.reasonCodes).toContain('clean.below_threshold');
    const signals = (final!.evidence as { signals: { name: string }[] }).signals.map((s) => s.name);
    expect(signals).toEqual(
      expect.arrayContaining(['R_SPF_ALLOW', 'R_DKIM_ALLOW', 'DMARC_POLICY_ALLOW']),
    );
    expect(signals).not.toContain('GTUBE');
    // Step 4.2 rule A0: no attachments → the attachment engine's final is `skipped`.
    const attachmentFinal = results.find((r) => r.engine === 'attachment');
    expect(attachmentFinal).toMatchObject({
      scanId: round.id,
      isFinal: true,
      attempt: 1,
      outcome: 'skipped',
      errorCode: null,
      reasonCodes: ['attachment.none'],
    });
    expect(
      await fx.prisma.attachmentScanResult.count({
        where: { messageId: message.id, receivedAt: message.receivedAt },
      }),
    ).toBe(0);

    const [auth, ...moreAuth] = await authResultsOf(fx.prisma, message);
    expect(moreAuth).toEqual([]);
    expect(auth).toMatchObject({
      scanId: round.id,
      engine: 'rspamd',
      spf: 'pass',
      spfDomain: 'clean.scan.test',
      dkim: 'pass',
      dmarc: 'pass',
      dmarcPolicy: 'reject',
      dmarcDomain: 'clean.scan.test',
    });
    expect(auth!.dkimSignatures).toEqual([
      { domain: 'clean.scan.test', result: 'pass', selector: 'eg2026' },
    ]);

    // One scanned.v1 (schema-valid, no symbols/options/addresses) and one ledger row.
    const scanned = await scannedEventsOf(fx.prisma, org, message);
    expect(scanned).toHaveLength(1);
    const payload = messageScannedV1.parse(scanned[0]!.payload);
    expect(payload).toMatchObject({
      messageId: message.id.toString(),
      lifecycleRound: 0,
      scanId: round.id.toString(),
      scanKind: 'initial',
      outcome: 'scanned',
      verdict: 'clean',
      emlS3Key: message.emlObjectKey,
    });
    expect([...payload.engines].sort((a, b) => a.engine.localeCompare(b.engine))).toEqual([
      { engine: 'attachment', required: true, outcome: 'skipped', attempts: 1 },
      { engine: 'rspamd', required: true, outcome: 'clean', attempts: 1 },
    ]);
    expect(JSON.stringify(scanned[0]!.payload)).not.toContain('clean.scan.test');
    for (const consumer of [RSPAMD_LEDGER, ATTACHMENT_LEDGER]) {
      expect(
        await fx.prisma.messageIdempotency.count({
          where: { consumer, eventId: parsed.eventId },
        }),
      ).toBe(1);
    }

    // Approved by the pass-through only after the scan (E27), then delivered.
    const [delivery] = await waitForAllDeliveries(fx.prisma, org, message.id, ['delivered'], 1);
    expect(delivery!.address).toBe(rcpt.toLowerCase());
    await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete');
    expect(await pathOf(fx.prisma, message)).toEqual(
      DELIVERED_PATH('delivered', 'delivery_complete'),
    );
    const history = await historyOf(fx.prisma, message);
    expect(history.slice(2, 5).map((h) => [h.toStatus, h.actorRole, h.actorService])).toEqual([
      ['scanning', 'scanner', 'email-worker'],
      ['scanned', 'scanner', 'email-worker'],
      ['approved', 'dev_passthrough', 'delivery-worker'],
    ]);
    // Causation (`event_id`): the parsed event opens and completes the round; the scanned
    // event causes the approval.
    expect(history.slice(2, 5).map((h) => h.eventId)).toEqual([
      parsed.eventId,
      parsed.eventId,
      scanned[0]!.eventId,
    ]);
    await expectConsistentHistory(fx.prisma, message);
    await expectStateChangedRows(fx.prisma, org, message);
    const approvals = await fx.prisma.messageOutbox.findMany({
      where: { organizationId: org, eventType: 'mail.delivery.approved.v1' },
    });
    expect(approvals).toHaveLength(1);
    expect(approvals[0]!.payload).toMatchObject({ source: 'dev_passthrough', lifecycleRound: 0 });
    const deliveredAfterMs = Date.now() - started;

    // The delivered copy carries exactly one Authentication-Results of ours.
    const [file] = await sinkFiles(rcpt);
    const delivered = (await sinkMessage(file!)).toString('utf8');
    const ours = headerFieldsOf(delivered).filter(
      (f) =>
        f.name.toLowerCase() === 'authentication-results' &&
        f.value.toLowerCase().startsWith(`${authservId.toLowerCase()};`),
    );
    expect(ours).toHaveLength(1);

    // The read API (replica) explains the verdict.
    const page = (await scansApi(await messagePublicId(fx.prisma, message), 1)) as {
      data: {
        round: number;
        verdict: string;
        auth: { spf: string; dkim: string; dmarc: string };
        engines: { engine: string; final: boolean; outcome: string; symbols: { name: string }[] }[];
      }[];
    };
    expect(page.data[0]).toMatchObject({
      round: 0,
      verdict: 'clean',
      auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass' },
      engines: [
        { engine: 'rspamd', final: true, outcome: 'clean' },
        { engine: 'attachment', final: true, outcome: 'skipped', reasonCodes: ['attachment.none'] },
      ],
    });
    expect(page.data[0]!.engines[0]!.symbols.map((s) => s.name)).toContain('R_SPF_ALLOW');
    cleanMessage = { id: message.id, receivedAt: message.receivedAt, rcpt };
    record('scan-pipeline', {
      clean_score: Number(final!.score),
      engine_version: final!.engineVersion,
      engine_ms: final!.durationMs,
      smtp_to_scanned_ms: scannedAfterMs,
      smtp_to_delivered_ms: deliveredAfterMs,
    });
  });

  it('accepts a spoofed message at SMTP time and scans it with auth.spf_fail and auth.dmarc_reject', async () => {
    const rcpt = `spoofed@${domain.name}`;
    const text = [
      // A forged pass under our authserv-id: removed at SMTP time, never trusted post-queue.
      `Authentication-Results: ${authservId}; spf=pass smtp.mailfrom=spoof.scan.test; dmarc=pass`,
      'From: "Chief Executive" <ceo@spoof.scan.test>',
      `To: ${rcpt}`,
      'Subject: Urgent wire transfer',
      `Message-ID: <spoof-${fx.suffix}@spoof.scan.test>`,
      `Date: ${new Date().toUTCString().replace('GMT', '+0000')}`,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=utf-8',
      '',
      'Please process the attached payment today.',
      '',
    ].join('\r\n');
    const sent = await sendToMx({
      from: 'ceo@spoof.scan.test',
      to: [rcpt],
      helo: 'mail.spoof-sender.scan.test',
      data: text,
    });
    expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
    const message = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
    expect(message.clientIp).toMatch(/^172\.31\.250\./);

    const round = await waitForRoundComplete(fx.prisma, message, 0);
    expect(round).toMatchObject({ status: 'completed', scanKind: 'initial' });
    expect(['suspicious', 'spam']).toContain(round.scanVerdict);
    const final = (await engineResultsOf(fx.prisma, message)).find(
      (r) => r.isFinal && r.engine === 'rspamd',
    );
    expect(final!.reasonCodes).toEqual(
      expect.arrayContaining(['auth.spf_fail', 'auth.dmarc_reject']),
    );
    expect(round.reasonCodes).toEqual(
      expect.arrayContaining(['auth.spf_fail', 'auth.dmarc_reject']),
    );
    const signals = (final!.evidence as { signals: { name: string }[] }).signals.map((s) => s.name);
    expect(signals).toEqual(expect.arrayContaining(['R_SPF_FAIL', 'DMARC_POLICY_REJECT']));
    const [auth] = await authResultsOf(fx.prisma, message);
    expect(auth).toMatchObject({
      spf: 'fail',
      spfDomain: 'spoof.scan.test',
      dmarc: 'fail',
      dmarcPolicy: 'reject',
      dmarcDomain: 'spoof.scan.test',
    });
    const scanned = await scannedEventsOf(fx.prisma, org, message);
    expect(messageScannedV1.parse(scanned[0]!.payload)).toMatchObject({
      outcome: 'scanned',
      verdict: round.scanVerdict,
    });

    // The stored EML: the forged pass is gone, ours reports the failure.
    const eml = (await fx.object(message.emlObjectKey)).toString('utf8');
    const ar = headerFieldsOf(eml).filter((f) => f.name.toLowerCase() === 'authentication-results');
    expect(ar).toHaveLength(1);
    expect(ar[0]!.value).toMatch(/spf=fail/);
    expect(ar[0]!.value).toMatch(/dmarc=fail/);

    // The development pass-through approves every scanned verdict (it stands in for a "deliver
    // everything scanned" policy, S15): delivered, with the scan in the path.
    await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete');
    expect(await pathOf(fx.prisma, message)).toEqual(
      DELIVERED_PATH('delivered', 'delivery_complete'),
    );
    record('scan-pipeline', {
      spoofed_verdict: round.scanVerdict,
      spoofed_score: Number(final!.score),
      spoofed_reasons: (final!.reasonCodes as string[]).join(','),
    });
  });

  it('treats duplicate scan triggers as no-ops: same event id (ledger) and a new event id (lifecycle)', async () => {
    expect(cleanMessage, 'the clean-message test must run first').toBeDefined();
    const message = { id: cleanMessage!.id, receivedAt: cleanMessage!.receivedAt };
    const parsedRow = await fx.prisma.messageOutbox.findFirstOrThrow({
      where: {
        organizationId: org,
        aggregateId: message.id.toString(),
        eventType: 'mail.message.parsed.v1',
      },
    });
    expect(parsedRow.publishedAt).not.toBeNull();
    const snapshot = async () => ({
      rounds: (await scanRoundsOf(fx.prisma, message)).map((r) => [r.id, r.status, r.scanVerdict]),
      results: (await engineResultsOf(fx.prisma, message)).map((r) => [r.id, r.isFinal]),
      auth: (await authResultsOf(fx.prisma, message)).length,
      scanned: (await scannedEventsOf(fx.prisma, org, message)).map((e) => e.eventId),
      history: (await historyOf(fx.prisma, message)).map((h) => h.toStatus),
      version: (
        await fx.prisma.emailMessage.findFirstOrThrow({
          where: { id: message.id, receivedAt: message.receivedAt },
          select: { version: true },
        })
      ).version,
      approvals: await fx.prisma.messageOutbox.count({
        where: { organizationId: org, eventType: 'mail.delivery.approved.v1' },
      }),
      sinkFiles: (await sinkFiles(cleanMessage!.rcpt)).length,
    });
    const before = await snapshot();
    expect(before.rounds).toHaveLength(1);
    expect(before.scanned).toHaveLength(1);

    // Both engine consumers (scan.spam and scan.attachment, step 4.2) get every copy.
    const skippedOf = (reason: string) =>
      Promise.all(
        REQUIRED_ENGINES.map((engine) =>
          metricValue('email-worker', 'scan_events_skipped_total', { engine, reason }),
        ),
      );
    const duplicatesBefore = await skippedOf('duplicate');
    const lifecycleSkipsBefore = await skippedOf('lifecycle_delivered');
    const grew = (now: number[], before: number[], by: number) =>
      now.every((v, i) => v >= before[i]! + by);
    const broker = await LiveBroker.connect();
    try {
      const deadLetters = await broker.depth(QUEUES.deadLetter);
      const exact = envelopeOfRow(parsedRow);
      // Twice: a broker redelivery-like copy and a relay-retry-like copy (same event id).
      await broker.publish([exact]);
      await broker.publish([exact]);
      // A re-emission of the same trigger under a new event id (not in the ledger).
      const reEmitted = { ...exact, eventId: randomUUID() };
      await broker.publish([reEmitted]);

      await waitFor(
        'two ledger duplicates and one lifecycle skip in each scan consumer',
        async () =>
          grew(await skippedOf('duplicate'), duplicatesBefore, 2) &&
          grew(await skippedOf('lifecycle_delivered'), lifecycleSkipsBefore, 1),
        { timeoutMs: 60_000, intervalMs: 500 },
      );
      await sleep(3_000);
      expect(await snapshot()).toEqual(before);
      expect(await broker.depth('scan.spam')).toBe(0);
      expect(await broker.depth('scan.attachment')).toBe(0);
      expect(await broker.depth(QUEUES.deadLetter)).toBe(deadLetters);
      // One ledger row per consumer and event id: the original and the re-emission (handled,
      // no effect).
      for (const consumer of [RSPAMD_LEDGER, ATTACHMENT_LEDGER]) {
        expect(
          await fx.prisma.messageIdempotency.count({
            where: { consumer, eventId: { in: [exact.eventId, reEmitted.eventId] } },
          }),
        ).toBe(2);
      }
      const duplicatesAfter = await skippedOf('duplicate');
      const lifecycleAfter = await skippedOf('lifecycle_delivered');
      record('scan-pipeline', {
        duplicate_copies: 3,
        ledger_duplicates: duplicatesAfter.map((v, i) => v - duplicatesBefore[i]!).join(','),
        lifecycle_skips: lifecycleAfter.map((v, i) => v - lifecycleSkipsBefore[i]!).join(','),
        second_effects: 0,
      });
    } finally {
      await broker.close();
    }
  });

  it('runs topology v4: scan.spam and scan.attachment consumed by the scanner user, scan.auth without event bindings', async () => {
    const scanner = process.env.RABBITMQ_SCANNER_USER || 'eg-scanner';
    for (const queue of ['scan.spam', 'scan.attachment']) {
      const details = await mgmt.get<{
        consumers?: number;
        consumer_details?: { channel_details?: { user?: string } }[];
      }>(`/queues/${encodeURIComponent(vhost)}/${queue}`);
      expect(details.consumers, queue).toBeGreaterThanOrEqual(1);
      expect(
        new Set((details.consumer_details ?? []).map((c) => c.channel_details?.user)),
        queue,
      ).toEqual(new Set([scanner]));
    }
    const auth = (await mgmt.bindings(vhost)).filter(
      (b) => b.source !== '' && b.destination === 'scan.auth',
    );
    expect(auth.map((b) => b.routing_key)).toEqual(['retry.scan.auth.#']);
    expect((await mgmt.queue(vhost, 'scan.auth')).consumers).toBe(0);
    // Every round of this suite was completed by the live consumer: nothing is left behind.
    const rounds = await fx.prisma.emailScan.findMany({ where: { organizationId: org } });
    expect(rounds).toHaveLength(2);
    expect(rounds.every((r) => r.status === 'completed')).toBe(true);
    for (const r of rounds) {
      expect(
        await scanRoundsOf(fx.prisma, { id: r.messageId, receivedAt: r.receivedAt }),
      ).toHaveLength(1);
    }
  });
});
