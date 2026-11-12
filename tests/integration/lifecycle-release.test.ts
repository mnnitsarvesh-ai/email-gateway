import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, type ApiSession } from './support/api-client';
import { waitFor } from './support/compose';
import { waitForAllDeliveries, waitForMessage } from './support/deliveries';
import {
  expectConsistentHistory,
  expectStateChangedRows,
  historyOf,
  insertFixtureMessage,
  lifecycleOf,
  pathOf,
  waitForLifecycle,
  type FixtureMessage,
} from './support/lifecycle';
import { clearSinkDomain, sinkFiles } from './support/mail-sink';
import { record } from './support/messaging-stack';
import { createAndPublishPolicy, waitForEvaluation } from './support/policy';
import {
  entriesOf,
  idem,
  releaseLogsOf,
  waitForEntries,
  waitForReleaseOutcome,
} from './support/quarantine';
import { MAIL_SINK_HOST, organizationRef } from './support/routing';
import { corpusEml, messagePublicId, scanStackGate, sendToMx } from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply } from './support/smtp-tools';
import { purgeDormantQueues } from './support/broker';

/**
 * Quarantine release through the LIVE api and the real delivery path (docs/plan/steps/
 * 08-message-lifecycle.md L10.3, rewritten for step 5.3: docs/plan/steps/17-quarantine.md Q13,
 * Q14, Q30, §9.3 "Regressions"). Since 5.3 a quarantined or held message is released per
 * recipient through the quarantine workflow; the step 3.3 route `POST /messages/{id}/release`
 * answers `409 quarantine_workflow_required` for every quarantined/held message.
 *
 * 1. A real scanned message (inbound through Postfix, quarantined by a tenant rule, one entry
 *    per recipient): the old route answers 409 and writes nothing; the operator releases the
 *    first entry (`POST /quarantine/entries/{id}/release`, Idempotency-Key: replay and reuse
 *    checked) → the policy-engine's executor re-validates and applies E14 (new round), the
 *    relay publishes the approval, the planner plans it (E20), Postfix delivers, the recorder
 *    derives `delivered` (`delivery_partial`: the second recipient is still held); releasing the
 *    second entry later is E28 (`quarantine_partial_release`) and each recipient is delivered
 *    exactly once.
 * 2. Regression of step 3.3 verification round 2 on the 5.3 path: a fixture message held before
 *    5.3 (no entries, adopted by the quarantine sweeper), two recipients, the first on a domain
 *    that is not the organization's; both entries released through approvals (no scan round →
 *    `no_scan_round`, approved by a second MFA user in one bulk request): the planner refuses the
 *    first recipient, the other is delivered, the message ends `delivered` / `delivery_partial`.
 */
const gate = await scanStackGate();
const fx = new SmtpFixtures();
let org = 0n;
let domain: FixtureDomain;
let analyst: ApiSession | undefined;
let admin: ApiSession | undefined;
let approver: ApiSession | undefined;

beforeAll(async () => {
  assertStackReady(gate);
  org = await fx.organization('lc-release');
  domain = await fx.domain(org, 'lc-release');
  await fx.destinations(domain, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  const ref = await organizationRef(fx, org);
  analyst = await apiSession(fx.prisma, ref, 'security_analyst');
  admin = await apiSession(fx.prisma, ref, 'organization_admin');
  approver = await apiSession(fx.prisma, ref, 'organization_admin', { mfa: true });
  await createAndPublishPolicy(analyst, admin, 'Release stack', {
    dslVersion: 'policy-dsl/1',
    direction: 'inbound',
    priority: 100,
    rules: [
      {
        id: 'hold-release-recipients',
        priority: 10,
        when: { field: 'recipient.local_part', op: 'in', value: ['rel-a', 'rel-b'] },
        actions: [{ type: 'QUARANTINE' }],
      },
    ],
  });
}, 300_000);

afterAll(async () => {
  if (gate.skip) return;
  for (const s of [analyst, admin, approver]) await s?.remove();
  if (domain) await clearSinkDomain(domain.name).catch(() => undefined);
  await fx.cleanup();
  await purgeDormantQueues();
}, 300_000);

describe.skipIf(gate.skip)('lifecycle stack: quarantine release', { timeout: 600_000 }, () => {
  it('releases a scanned, quarantined message per entry through the quarantine api; the old route answers 409; each recipient is delivered once', async () => {
    const recipients = [`rel-a@${domain.name}`, `rel-b@${domain.name}`];
    const sent = await sendToMx({
      from: 'alice@clean.scan.test',
      to: recipients,
      helo: 'mx.clean.scan.test',
      data: corpusEml('clean/clean-dkim-aligned.eml'),
    });
    expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
    const row = await waitForMessage(fx.prisma, org, { mtaQueueId: sent.queueId! });
    const message = {
      id: row.id,
      receivedAt: row.receivedAt,
      publicId: await messagePublicId(fx.prisma, row),
    };
    const evaluation = await waitForEvaluation(fx.prisma, message);
    expect(evaluation).toMatchObject({
      disposition: 'quarantine',
      decisiveRuleId: 'hold-release-recipients',
    });
    const entries = await waitForEntries(fx.prisma, message, 2);
    const held = await waitForLifecycle(fx.prisma, message, 'quarantined', 'policy_quarantine');

    // The step 3.3 route: 409 quarantine_workflow_required, nothing written.
    const oldPath = `/messages/${message.publicId}/release`;
    const oldBody = { expectedVersion: held.version, reason: 'stack test: old route' };
    const missing = await admin!.post(oldPath, oldBody);
    expect(missing.status).toBe(400);
    expect(missing.body).toMatchObject({ code: 'idempotency_key_required' });
    const refused = await admin!.post(oldPath, oldBody, idem('old-release'));
    expect(refused.status, JSON.stringify(refused.body)).toBe(409);
    expect(refused.body).toMatchObject({
      code: 'quarantine_workflow_required',
      entries: 2,
      route: expect.stringContaining('/quarantine/entries/'),
    });
    expect(await lifecycleOf(fx.prisma, message)).toMatchObject({ version: held.version });

    // Release the first entry (operator, pre-check `release` → queued), with replay checks.
    const [first, second] = entries;
    const key = idem('release-a');
    const body = { reason: 'stack test: false positive, release to inbox' };
    const path = `/quarantine/entries/${first!.publicId}/release`;
    const queued = await analyst!.post(path, body, key);
    expect(queued.status, JSON.stringify(queued.body)).toBe(202);
    expect(queued.body).toMatchObject({ outcome: 'queued', state: 'releasing' });
    const replay = await analyst!.post(path, body, key);
    expect(replay.status).toBe(202);
    expect(replay.headers.get('idempotency-replayed')).toBe('true');
    expect(replay.body).toEqual(queued.body);
    const reused = await analyst!.post(path, { reason: 'a different operator reason text' }, key);
    expect(reused.status).toBe(422);
    expect(reused.body).toMatchObject({ code: 'idempotency_key_reused' });

    const releaseId = (queued.body as { releaseId: string }).releaseId;
    const started = Date.now();
    const [log] = await waitForReleaseOutcome(fx.prisma, releaseId);
    expect(log).toMatchObject({
      status: 'dispatched',
      mode: 'operator',
      lifecycleRoundAfter: 1,
      // `deliverySeq` = highest + 1 (Q13.2): no earlier approval exists, so 0 (the 3.3 route used 1).
      deliverySeq: 0,
      deliveredObject: 'policy_copy',
    });
    const firstDeliveries = await waitForAllDeliveries(
      fx.prisma,
      org,
      message.id,
      ['delivered'],
      1,
      180_000,
    );
    expect(firstDeliveries.map((d) => d.deliverySeq)).toEqual([0]);
    await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_partial', 180_000);
    const deliveredAfterMs = Date.now() - started;
    expect(await sinkFiles(recipients[0]!)).toHaveLength(1);
    expect(await sinkFiles(recipients[1]!)).toEqual([]);

    // The second entry later: E28 delivered → approved, a new round, delivered once.
    const second202 = await analyst!.post(
      `/quarantine/entries/${second!.publicId}/release`,
      body,
      idem('release-b'),
    );
    expect(second202.status, JSON.stringify(second202.body)).toBe(202);
    const [log2] = await waitForReleaseOutcome(
      fx.prisma,
      (second202.body as { releaseId: string }).releaseId,
    );
    expect(log2).toMatchObject({ status: 'dispatched', lifecycleRoundAfter: 2, deliverySeq: 1 });
    await waitForAllDeliveries(fx.prisma, org, message.id, ['delivered'], 2, 180_000);
    await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_complete', 180_000);
    for (const rcpt of recipients) expect(await sinkFiles(rcpt)).toHaveLength(1);

    const fullPath = await pathOf(fx.prisma, message);
    const at = fullPath.findIndex(([, to]) => to === 'quarantined');
    expect(fullPath.slice(at)).toEqual([
      ['policy_evaluated', 'quarantined', 'policy_quarantine'],
      ['quarantined', 'approved', 'quarantine_release'],
      ['approved', 'delivery_pending', 'delivery_planned'],
      ['delivery_pending', 'delivered', 'delivery_partial'],
      ['delivered', 'approved', 'quarantine_partial_release'],
      ['approved', 'delivery_pending', 'delivery_planned'],
      ['delivery_pending', 'delivered', 'delivery_complete'],
    ]);
    await expectConsistentHistory(fx.prisma, message);
    await expectStateChangedRows(fx.prisma, org, message);
    const history = await historyOf(fx.prisma, message);
    const release = history.find((h) => h.reasonCode === 'quarantine_release')!;
    expect(release).toMatchObject({
      actorRole: 'quarantine',
      actorService: 'policy-engine',
      lifecycleRound: 1,
    });
    const partial = history.find((h) => h.reasonCode === 'quarantine_partial_release')!;
    expect(partial).toMatchObject({ actorRole: 'quarantine', lifecycleRound: 2 });

    // One approval per release, one planner ledger row each, one audit row per request.
    const approvals = await fx.prisma.messageOutbox.findMany({
      where: { organizationId: org, eventType: 'mail.delivery.approved.v1' },
    });
    expect(
      approvals.map((a) => [
        (a.payload as { source: string }).source,
        (a.payload as { deliverySeq: number }).deliverySeq,
      ]),
    ).toEqual([
      ['quarantine_release', 0],
      ['quarantine_release', 1],
    ]);
    expect(
      await fx.prisma.messageIdempotency.count({
        where: {
          consumer: 'delivery-worker.planner',
          eventId: { in: approvals.map((a) => a.eventId) },
        },
      }),
    ).toBe(2);
    expect(
      await fx.prisma.auditLog.count({
        where: { organizationId: org, action: 'quarantine.release_requested' },
      }),
    ).toBe(2);
    expect(
      (await entriesOf(fx.prisma, message)).map((e) => [e.recipientAddress, e.status]),
    ).toEqual([
      [recipients[0], 'released'],
      [recipients[1], 'released'],
    ]);
    // The lifecycle read API (replica, lag fallback): no release action any more.
    await waitFor(
      'the lifecycle read API to show delivered',
      async () => {
        const res = await analyst!.get(`/messages/${message.publicId}/lifecycle`);
        return res.status === 200 && (res.body as { lifecycleRound?: number }).lifecycleRound === 2
          ? res
          : undefined;
      },
      { timeoutMs: 30_000, intervalMs: 500 },
    ).then((res) =>
      expect(res.body).toMatchObject({
        state: 'delivered',
        statusReason: 'delivery_complete',
        recipients: { total: 2, byStatus: { delivered: 2 } },
        actions: { release: false },
      }),
    );
    record('lifecycle-release', {
      recipients: 2,
      delivered_after_release_s: (deliveredAfterMs / 1000).toFixed(1),
      history_rows: history.length,
    });
  });

  it('a refused first recipient does not finish the release: adopted entries approved in bulk, the other recipient delivered, delivery_partial', async () => {
    // Regression (step 3.3 verification round 2) on the 5.3 path: the release turns the
    // released quarantined recipients into `pending`, so the planner's refusal of recipient 0
    // cannot derive `rejected` while recipient 1 still reads as settled.
    // Inbound: the planner refuses a recipient whose domain is not a domain of the organization
    // (`recipient_domain_inactive`, delivery `failed`); suppressions apply to outbound only.
    const refusedRcpt = `rel-x@not-a-tenant-${fx.suffix}.test`;
    const kept = `rel-k@${domain.name}`;
    // A message held before 5.3 (fixture rows, L8.6): the quarantine sweeper adopts it (Q8).
    const message: FixtureMessage = await insertFixtureMessage(fx, {
      organizationId: org,
      domainId: domain.id,
      state: 'quarantined',
      recipients: [refusedRcpt, kept],
      recipientStatus: 'quarantined',
      subject: 'Lifecycle release, one recipient refused',
    });
    const entries = await waitForEntries(fx.prisma, message, 2, { timeoutMs: 240_000 });
    expect(entries.map((e) => [e.origin, e.status])).toEqual([
      ['adopted', 'held'],
      ['adopted', 'held'],
    ]);
    // Release both (bulk): no completed scan round → approval needed (`no_scan_round`).
    const requested = await analyst!.post(
      '/quarantine/bulk',
      {
        action: 'release',
        ids: entries.map((e) => e.publicId),
        reason: 'stack test: release with a refused rcpt',
      },
      idem('bulk-release'),
    );
    expect(requested.status, JSON.stringify(requested.body)).toBe(200);
    const results = (
      requested.body as {
        results: { status: string; approvalRequestId?: string }[];
      }
    ).results;
    expect(results.map((r) => r.status)).toEqual(['approval_requested', 'approval_requested']);
    const approvals = await fx.prisma.quarantineApprovalRequest.findMany({
      where: { publicId: { in: results.map((r) => r.approvalRequestId!) } },
    });
    for (const a of approvals) expect(a.approvalReasons).toEqual(['no_scan_round']);
    // A second user (MFA) approves both in one bulk request.
    const approved = await approver!.post(
      '/quarantine/bulk',
      {
        action: 'approve',
        ids: results.map((r) => r.approvalRequestId!),
        reason: 'stack test: approved',
      },
      idem('bulk-approve'),
    );
    expect(approved.status, JSON.stringify(approved.body)).toBe(200);
    const approvedResults = (approved.body as { results: { status: string; releaseId: string }[] })
      .results;
    expect(approvedResults.map((r) => r.status)).toEqual(['queued', 'queued']);
    for (const r of approvedResults) {
      const [log] = await waitForReleaseOutcome(fx.prisma, r.releaseId);
      expect(log).toMatchObject({ status: 'dispatched', mode: 'approved' });
    }
    const deliveries = await waitForAllDeliveries(
      fx.prisma,
      org,
      message.id,
      ['delivered', 'failed'],
      2,
      180_000,
    );
    expect(deliveries.map((d) => d.status).sort()).toEqual(['delivered', 'failed']);
    await waitForLifecycle(fx.prisma, message, 'delivered', 'delivery_partial', 180_000);
    expect(await sinkFiles(kept)).toHaveLength(1);
    const path = await pathOf(fx.prisma, message);
    expect(path.slice(0, 4)).toEqual([
      [null, 'received', 'smtp_accepted'],
      ['received', 'persisted', 'committed'],
      ['persisted', 'quarantined', 'policy_quarantine'],
      ['quarantined', 'approved', 'quarantine_release'],
    ]);
    expect(path.at(-1)).toEqual(['delivery_pending', 'delivered', 'delivery_partial']);
    await expectConsistentHistory(fx.prisma, message);
    expect(
      (await releaseLogsOf(fx.prisma, approvedResults[0]!.releaseId))[0]!.approvalRequestId,
    ).not.toBeNull();
  });
});
